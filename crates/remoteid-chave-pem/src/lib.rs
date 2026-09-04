//! Adaptador da chave da instalação em arquivo PEM: o `installation-key.pem`.
//!
//! Implementa a porta [`remoteid_portas::CofreDeChave`]. A chave privada **nunca
//! sai do cofre**: o adaptador expõe só operações de assinatura e a chave
//! pública. Trocar para Postgres/HSM é implementar a mesma porta em outro crate.
//!
//! A criptografia pura está em [`remoteid_cripto`]; aqui fica só o I/O de disco:
//! ler o PEM, ou gerá-lo (0600 desde a criação) na primeira vez.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use remoteid_cripto::ChaveInstalacao;
use remoteid_portas::CofreDeChave;
use remoteid_tipos::{Error, IdInstalacao, Result};

/// Carrega a chave de `caminho`, gerando-a (e gravando-a 0600) se não existir.
///
/// Gerar uma chave nova quando já havia uma invalidaria o `codigoDesktop` já
/// registrado, então a existência do arquivo é respeitada.
pub fn carregar_ou_gerar(caminho: &Path) -> Result<ChaveInstalacao> {
    if caminho.exists() {
        return carregar(caminho);
    }
    if let Some(pai) = caminho.parent() {
        fs::create_dir_all(pai)?;
    }
    let chave = ChaveInstalacao::gerar()?;
    escrever_privado(caminho, chave.to_pkcs8_pem()?.as_bytes())?;
    Ok(chave)
}

/// Carrega uma chave existente (PKCS#8 ou PKCS#1). Falha se não existir ou não
/// for uma chave RSA em PEM.
pub fn carregar(caminho: &Path) -> Result<ChaveInstalacao> {
    let pem = fs::read_to_string(caminho)?;
    ChaveInstalacao::de_pem(&pem).map_err(|_| {
        Error::cripto(format!(
            "{} não é uma chave RSA em PEM (PKCS#8 nem PKCS#1)",
            caminho.display()
        ))
    })
}

/// Grava um arquivo com 0600 DESDE A CRIAÇÃO: criar aberto e ajustar depois
/// deixa uma janela em que a chave privada existe legível por outros.
fn escrever_privado(caminho: &Path, conteudo: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(caminho)?;
    f.write_all(conteudo)?;
    f.sync_all()?;
    Ok(())
}

/// O adaptador: guarda as chaves sob um diretório base, uma
/// `installation-key.pem` por instalação (`local` mora direto em `base/`,
/// as demais em `base/<id>/`), carregando-as sob demanda e mantendo-as em
/// memória enquanto o cofre viver.
pub struct CofrePem {
    base: PathBuf,
    cache: Mutex<HashMap<String, Arc<ChaveInstalacao>>>,
}

impl CofrePem {
    pub fn novo(base: impl Into<PathBuf>) -> Self {
        CofrePem {
            base: base.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn caminho(&self, id: &IdInstalacao) -> PathBuf {
        let dir = if *id == IdInstalacao::local() {
            self.base.clone()
        } else {
            self.base.join(id.como_str())
        };
        dir.join("installation-key.pem")
    }

    /// A chave da instalação, carregada-ou-gerada e mantida em cache.
    fn chave(&self, id: &IdInstalacao) -> Result<Arc<ChaveInstalacao>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cache.get(id.como_str()) {
            return Ok(Arc::clone(c));
        }
        let chave = Arc::new(carregar_ou_gerar(&self.caminho(id))?);
        cache.insert(id.como_str().to_string(), Arc::clone(&chave));
        Ok(chave)
    }
}

impl CofreDeChave for CofrePem {
    fn publica_pem(&self, id: &IdInstalacao) -> Result<String> {
        self.chave(id)?.publica_pem()
    }
    fn assinar_digest(&self, id: &IdInstalacao, digest: &[u8]) -> Result<Vec<u8>> {
        self.chave(id)?.assinar_digest(digest)
    }
    fn assinar_pkcs1_v15_cru(&self, id: &IdInstalacao, dados: &[u8]) -> Result<Vec<u8>> {
        self.chave(id)?.assinar_pkcs1_v15_cru(dados)
    }
    fn bearer_assinado(&self, id: &IdInstalacao, canonical: &str) -> Result<String> {
        self.chave(id)?.bearer_assinado(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoteid_cripto::sha256;

    #[test]
    fn reusa_a_chave_existente_em_vez_de_gerar_outra() {
        let dir = std::env::temp_dir().join(format!("rid-cofre-reuso-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cofre = CofrePem::novo(&dir);
        let id = IdInstalacao::local();
        let pub1 = cofre.publica_pem(&id).unwrap();
        // Reabrir de um cofre novo (sem cache) tem de dar a mesma chave pública.
        let pub2 = CofrePem::novo(&dir).publica_pem(&id).unwrap();
        assert_eq!(pub1, pub2);
        assert!(pub1.starts_with("-----BEGIN PUBLIC KEY-----"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn assina_e_o_bearer_e_deterministico() {
        let dir = std::env::temp_dir().join(format!("rid-cofre-assina-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cofre = CofrePem::novo(&dir);
        let id = IdInstalacao::local();
        let sig = cofre.assinar_digest(&id, &sha256(b"conteudo")).unwrap();
        assert_eq!(sig.len(), 256, "RSA-2048 assina em 256 bytes");
        let a = cofre.bearer_assinado(&id, "mesmo corpo").unwrap();
        let b = cofre.bearer_assinado(&id, "mesmo corpo").unwrap();
        assert_eq!(a, b, "PKCS#1 v1.5 não tem sal: mesmo corpo, mesmo Bearer");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_chave_nasce_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rid-cofre-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        CofrePem::novo(&dir)
            .publica_pem(&IdInstalacao::local())
            .unwrap();
        let modo = fs::metadata(dir.join("installation-key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(modo, 0o600, "a chave privada não pode nascer legível");
        let _ = fs::remove_dir_all(&dir);
    }
}
