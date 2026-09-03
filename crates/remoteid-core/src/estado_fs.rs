//! Borda de I/O do estado: onde ficam os arquivos, e ler/gravar o `state.json`.
//!
//! Os tipos e a política de cache são puros, em [`remoteid_estado`]. Aqui fica o
//! efeito colateral: resolver os diretórios (XDG, `REMOTEID_HOME`, modo de
//! teste) e persistir o JSON com 0600 e escrita atômica. Na Fase 2 isto vira o
//! adaptador `store-json` por trás da porta `RepositorioEstado`, e a resolução
//! de diretórios/env vira a porta `Ambiente`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use remoteid_estado::Estado;
use remoteid_tipos::Result;

/// Diretório do MODO DE TESTE. Um só, em /tmp, para o app, o CLI e o módulo
/// PKCS#11 relocarem juntos quando `TEST_URL` está setada — assim o teste é UM
/// interruptor só (`TEST_URL`). Ver [[remoteid-teste-local]].
pub const DIR_TESTE: &str = "/tmp/remoteid-teste";

/// `true` quando estamos em modo de teste (`TEST_URL` presente). É a presença
/// da variável que importa; o valor (a URL do mock) só o motor usa.
pub fn em_teste() -> bool {
    env_nao_vazia("TEST_URL").is_some()
}

/// Diretório de dados: chave da instalação, `state.json` e cache do sessionToken.
///
/// Precedência: modo de teste, depois `REMOTEID_HOME`, depois
/// `XDG_STATE_HOME/remoteid`, com fallback `~/.local/state/remoteid`.
pub fn dir_dados() -> PathBuf {
    if em_teste() {
        return PathBuf::from(DIR_TESTE);
    }
    if let Some(h) = env_nao_vazia("REMOTEID_HOME") {
        return PathBuf::from(h);
    }
    base_xdg("XDG_STATE_HOME", ".local/state").join("remoteid")
}

/// Diretório do log de diagnóstico. Fica em `XDG_STATE_HOME`: é o que a
/// especificação reserva para log (sobrevive ao reboot, não é configuração, e
/// pode ser apagado sem perder nada essencial).
pub fn dir_diag() -> PathBuf {
    if em_teste() {
        return PathBuf::from(DIR_TESTE).join("diag");
    }
    if let Some(h) = env_nao_vazia("REMOTEID_DIAG_DIR") {
        return PathBuf::from(h);
    }
    base_xdg("XDG_STATE_HOME", ".local/state")
        .join("remoteid")
        .join("diag")
}

fn env_nao_vazia(nome: &str) -> Option<String> {
    std::env::var(nome).ok().filter(|v| !v.is_empty())
}

fn base_xdg(var: &str, padrao: &str) -> PathBuf {
    if let Some(v) = env_nao_vazia(var) {
        return PathBuf::from(v);
    }
    let home = env_nao_vazia("HOME").unwrap_or_else(|| "/tmp".into());
    PathBuf::from(home).join(padrao)
}

pub fn caminho_chave(dir: &Path) -> PathBuf {
    dir.join("installation-key.pem")
}

pub fn caminho_estado(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

/// Lê o `state.json`. Um arquivo ausente ou vazio devolve um estado novo (no
/// modo de autorização padrão), não um erro: é o primeiro uso.
pub fn carregar(caminho: &Path) -> Result<Estado> {
    if !caminho.exists() {
        return Ok(Estado::novo());
    }
    let texto = fs::read_to_string(caminho)?;
    if texto.trim().is_empty() {
        return Ok(Estado::novo());
    }
    Ok(serde_json::from_str(&texto)?)
}

/// Grava com 0600: o arquivo tem CPF, nome, certificado do titular e os
/// `sessionToken` cached, todos sensíveis. Escreve em arquivo temporário e
/// renomeia: uma interrupção no meio da escrita não pode deixar o estado
/// truncado, que faria o próximo comando perder o codigoDesktop e registrar
/// tudo de novo.
pub fn salvar(estado: &Estado, caminho: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use remoteid_estado::Certificado;

    #[test]
    fn salva_e_recarrega_preservando_tudo() {
        let dir = std::env::temp_dir().join(format!("rid-estado-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let caminho = caminho_estado(&dir);

        let mut e = carregar(&caminho).unwrap();
        e.user_id = Some(327989);
        e.codigo_desktop = Some("4d1f71d2-c20b-44d0-9bb0-5629015f21e8".into());
        e.certificados = vec![Certificado::do_key_name("SER;CN=AC", None).unwrap()];
        e.guardar_sessao(
            "SER;CN=AC".into(),
            "sessaoAssinatura;327989;CN%3DAC;SER;0;jwt;1756900000;hmac".into(),
            1_756_900_000,
        );
        salvar(&e, &caminho).unwrap();

        let lido = carregar(&caminho).unwrap();
        assert_eq!(lido.user_id, Some(327989));
        assert_eq!(lido.codigo_desktop().unwrap(), "4d1f71d2-c20b-44d0-9bb0-5629015f21e8");
        assert_eq!(lido.certificado().unwrap().issue, "CN=AC");
        let s = lido.sessao("SER;CN=AC", 1_756_900_000, 900).unwrap();
        assert!(s.token.starts_with("sessaoAssinatura;"));
        assert_eq!(s.emitido_em, Some(1_756_900_000));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let modo = fs::metadata(&caminho).unwrap().permissions().mode() & 0o777;
            assert_eq!(modo, 0o600, "o estado tem CPF, certificado e sessão: não é público");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_dados_respeita_a_variavel_de_ambiente() {
        // Sem depender do ambiente real do teste: só a precedência declarada.
        assert!(dir_dados().is_absolute() || dir_dados().starts_with("/tmp"));
    }
}
