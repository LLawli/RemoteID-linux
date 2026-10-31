//! Onde o RemoteID guarda as coisas, e com que servidor fala.
//!
//! Dentro do Flatpak o `XDG_STATE_HOME` é o do Âncora
//! (`~/.var/app/dev.lukakuuhaku.Ancora/.local/state`), que o módulo PKCS#11 e
//! a janela dividem, porque os dois rodam no sandbox dele.

use std::env;
use std::path::PathBuf;

use crate::protocolo::Servidor;

/// Troca o diretório inteiro. Os testes usam um diretório descartável.
pub const ENV_DIRETORIO: &str = "REMOTEID_HOME";

/// Troca os dois serviços da Certisign por um só endereço: o servidor falso.
pub const ENV_SERVIDOR: &str = "REMOTEID_SERVIDOR";

#[derive(Debug, Clone)]
pub struct Caminhos {
    pub raiz: PathBuf,
}

impl Caminhos {
    pub fn do_ambiente() -> Caminhos {
        let raiz = env::var_os(ENV_DIRETORIO)
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| xdg_state().join("remoteid"));
        Caminhos { raiz }
    }

    pub fn estado(&self) -> PathBuf {
        self.raiz.join("estado.json")
    }

    /// A chave desta instalação, a que assina o `Bearer`. Não é a do
    /// certificado, que nunca sai do HSM da Certisign.
    pub fn chave(&self) -> PathBuf {
        self.raiz.join("chave-instalacao.pem")
    }

    /// A senha da conta cifrada com o PIN local, quando não há chaveiro.
    pub fn senha_cifrada(&self) -> PathBuf {
        self.raiz.join("senha.cifrada")
    }

    pub fn diagnostico(&self) -> PathBuf {
        self.raiz.join("diagnostico")
    }
}

fn xdg_state() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".local/state")
        })
}

/// O servidor de produção, ou o falso quando [`ENV_SERVIDOR`] diz.
pub fn servidor() -> Servidor {
    match env::var(ENV_SERVIDOR) {
        Ok(url) if !url.is_empty() => Servidor::falso(&url),
        _ => Servidor::producao(),
    }
}
