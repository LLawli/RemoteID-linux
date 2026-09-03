//! Borda de I/O da chave da instalação: ler/gerar/gravar o PEM em disco.
//!
//! A criptografia pura (gerar o par, assinar, serializar) mora em
//! [`remoteid_cripto`]. Aqui fica só o efeito colateral de disco, que na Fase 2
//! vira o adaptador `chave-pem` por trás da porta `CofreDeChave`. Por isso a
//! chave privada é gravada com 0600 desde a criação, e nunca reaberta legível.

use std::fs;
use std::io::Write;
use std::path::Path;

use remoteid_cripto::ChaveInstalacao;
use remoteid_tipos::{Error, Result};

/// Carrega a chave de `caminho`, gerando-a (e gravando-a) se ainda não existir.
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

/// Carrega uma chave existente. Aceita PKCS#8 e PKCS#1 (o harness antigo em
/// Python usava `openssl genrsa`, que escreve PKCS#1). Falha se o arquivo não
/// existir ou não for uma chave RSA em PEM.
pub fn carregar(caminho: &Path) -> Result<ChaveInstalacao> {
    let pem = fs::read_to_string(caminho)?;
    ChaveInstalacao::de_pem(&pem).map_err(|_| {
        Error::cripto(format!(
            "{} não é uma chave RSA em PEM (PKCS#8 nem PKCS#1)",
            caminho.display()
        ))
    })
}

/// Grava um arquivo com 0600 DESDE A CRIAÇÃO.
///
/// Criar aberto e ajustar depois deixa uma janela em que a chave privada existe
/// legível por outros.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reusa_a_chave_existente_em_vez_de_gerar_outra() {
        let dir = std::env::temp_dir().join(format!("rid-reuso-{}", std::process::id()));
        let caminho = dir.join("k.pem");
        let _ = fs::remove_dir_all(&dir);

        let pub1 = carregar_ou_gerar(&caminho).unwrap().publica_pem().unwrap();
        let pub2 = carregar_ou_gerar(&caminho).unwrap().publica_pem().unwrap();
        // Gerar uma chave nova invalidaria o codigoDesktop já registrado.
        assert_eq!(pub1, pub2);
        assert!(pub1.starts_with("-----BEGIN PUBLIC KEY-----"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_chave_nasce_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rid-perm-{}", std::process::id()));
        let caminho = dir.join("k.pem");
        let _ = fs::remove_dir_all(&dir);
        carregar_ou_gerar(&caminho).unwrap();
        let modo = fs::metadata(&caminho).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o600, "a chave privada não pode nascer legível");
        let _ = fs::remove_dir_all(&dir);
    }
}
