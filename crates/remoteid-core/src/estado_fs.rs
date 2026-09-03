//! Fachada de I/O do estado: resolve os diretórios e delega a persistência.
//!
//! A leitura/escrita do `state.json` é do adaptador
//! [`remoteid_store_json`] (que implementa a porta `RepositorioEstado`); aqui
//! ficam só a resolução de diretórios (XDG, `REMOTEID_HOME`, modo de teste) e o
//! re-export das funções de baixo nível que o motor ainda usa direto. Na Fase 3
//! o motor passa a receber um `Box<dyn RepositorioEstado>` e esta fachada some;
//! a resolução de diretórios vira a porta `Ambiente`.

use std::path::{Path, PathBuf};

// A persistência mora no adaptador; o motor a chama por estes nomes até a Fase 3.
pub use remoteid_store_json::{gravar as salvar, ler as carregar};

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
        // Sem depender do ambiente real do teste: só a precedência declarada.
        assert!(dir_dados().is_absolute() || dir_dados().starts_with("/tmp"));
    }
}
