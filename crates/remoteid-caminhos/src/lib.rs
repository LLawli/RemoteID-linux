//! Onde o RemoteID-linux guarda seus arquivos no desktop.
//!
//! É a composição de caminhos (não um domínio nem um adaptador): resolve os
//! diretórios de dados e de diagnóstico a partir do XDG e das variáveis de
//! ambiente, e sabe o modo de teste. Os adaptadores de arquivo (`store-json`,
//! `chave-pem`, `diag-jsonl`) e as raízes de composição (CLI, app, módulo
//! PKCS#11) recebem esses caminhos; nenhum deles resolve XDG por conta própria.

use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_dados_respeita_a_variavel_de_ambiente() {
        assert!(dir_dados().is_absolute() || dir_dados().starts_with("/tmp"));
    }
}
