//! Adaptador de armazenamento do estado em JSON: o `state.json` padrão.
//!
//! Implementa a porta [`remoteid_portas::RepositorioEstado`]. É o adaptador de
//! borda que a instalação usa logo após instalar; trocá-lo por XML ou Postgres
//! é implementar a mesma porta em outro crate, sem tocar no núcleo.
//!
//! O arquivo é gravado com 0600 (tem CPF, nome, certificado e os `sessionToken`
//! cached) e por escrita atômica (temporário + rename): uma interrupção no meio
//! não pode deixar o estado truncado, o que faria o próximo comando perder o
//! `codigoDesktop` e registrar tudo de novo.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use remoteid_estado::Estado;
use remoteid_portas::RepositorioEstado;
use remoteid_tipos::{IdInstalacao, Result};

/// Lê o `state.json` de `caminho`. Um arquivo ausente ou vazio devolve um estado
/// novo (no modo padrão), não um erro: é o primeiro uso.
pub fn ler(caminho: &Path) -> Result<Estado> {
    if !caminho.exists() {
        return Ok(Estado::novo());
    }
    let texto = fs::read_to_string(caminho)?;
    if texto.trim().is_empty() {
        return Ok(Estado::novo());
    }
    Ok(serde_json::from_str(&texto)?)
}

/// Grava o estado em `caminho` com 0600 e escrita atômica.
pub fn gravar(estado: &Estado, caminho: &Path) -> Result<()> {
    if let Some(pai) = caminho.parent() {
        fs::create_dir_all(pai)?;
    }
    let mut texto = serde_json::to_string_pretty(estado)?;
    texto.push('\n');

    let tmp = caminho.with_extension("json.tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp)?;
        f.write_all(texto.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, caminho)?;
    Ok(())
}

/// Apaga o `state.json`. Ausência não é erro.
pub fn apagar_arquivo(caminho: &Path) -> Result<()> {
    match fs::remove_file(caminho) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// O adaptador: guarda os estados sob um diretório base, um `state.json` por
/// instalação. A instalação `local` (o desktop) mora direto em
/// `base/state.json`; qualquer outra em `base/<id>/state.json`, o que já deixa
/// o mesmo processo servir várias contas sem colidir arquivos.
pub struct RepositorioJson {
    base: PathBuf,
}

impl RepositorioJson {
    pub fn novo(base: impl Into<PathBuf>) -> Self {
        RepositorioJson { base: base.into() }
    }

    fn caminho(&self, id: &IdInstalacao) -> PathBuf {
        if *id == IdInstalacao::local() {
            self.base.join("state.json")
        } else {
            self.base.join(id.como_str()).join("state.json")
        }
    }
}

impl RepositorioEstado for RepositorioJson {
    fn carregar(&self, id: &IdInstalacao) -> Result<Estado> {
        ler(&self.caminho(id))
    }
    fn salvar(&self, id: &IdInstalacao, estado: &Estado) -> Result<()> {
        gravar(estado, &self.caminho(id))
    }
    fn apagar(&self, id: &IdInstalacao) -> Result<()> {
        apagar_arquivo(&self.caminho(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoteid_estado::Certificado;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Adaptador ALTERNATIVO em memória, só para provar que a porta é uma
    /// costura real: o mesmo código de exercício roda contra JSON e contra este
    /// sem saber a diferença. É o embrião da prova de troca de implementação.
    #[derive(Default)]
    struct RepositorioMemoria {
        dados: Mutex<HashMap<String, Estado>>,
    }
    impl RepositorioEstado for RepositorioMemoria {
        fn carregar(&self, id: &IdInstalacao) -> Result<Estado> {
            Ok(self
                .dados
                .lock()
                .unwrap()
                .get(id.como_str())
                .cloned()
                .unwrap_or_else(Estado::novo))
        }
        fn salvar(&self, id: &IdInstalacao, estado: &Estado) -> Result<()> {
            self.dados.lock().unwrap().insert(id.como_str().to_string(), estado.clone());
            Ok(())
        }
        fn apagar(&self, id: &IdInstalacao) -> Result<()> {
            self.dados.lock().unwrap().remove(id.como_str());
            Ok(())
        }
    }

    /// Exercício agnóstico à implementação: grava, relê, apaga.
    fn exercitar(repo: &dyn RepositorioEstado) {
        let id = IdInstalacao::local();
        assert!(repo.carregar(&id).unwrap().codigo_desktop().is_err());

        let mut e = Estado::novo();
        e.user_id = Some(327989);
        e.codigo_desktop = Some("4d1f71d2".into());
        e.certificados = vec![Certificado::do_key_name("SER;CN=AC", None).unwrap()];
        e.guardar_sessao(
            "SER;CN=AC".into(),
            "sessaoAssinatura;327989;CN%3DAC;SER;0;jwt;1756900000;hmac".into(),
            1_756_900_000,
        );
        repo.salvar(&id, &e).unwrap();

        let lido = repo.carregar(&id).unwrap();
        assert_eq!(lido.user_id, Some(327989));
        assert_eq!(lido.certificado().unwrap().issue, "CN=AC");
        assert_eq!(lido.sessao("SER;CN=AC", 1_756_900_000, 900).unwrap().emitido_em, Some(1_756_900_000));

        repo.apagar(&id).unwrap();
        assert!(repo.carregar(&id).unwrap().codigo_desktop().is_err());
    }

    #[test]
    fn a_porta_isola_de_verdade_json_e_memoria_passam_o_mesmo_exercicio() {
        let dir = std::env::temp_dir().join(format!("rid-storejson-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        exercitar(&RepositorioJson::novo(&dir));
        exercitar(&RepositorioMemoria::default());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn o_state_json_nasce_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rid-storejson-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let repo = RepositorioJson::novo(&dir);
        repo.salvar(&IdInstalacao::local(), &Estado::novo()).unwrap();
        let modo = fs::metadata(dir.join("state.json")).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o600, "o estado tem CPF, certificado e sessão: não é público");
        let _ = fs::remove_dir_all(&dir);
    }
}
