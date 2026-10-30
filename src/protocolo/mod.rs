//! O protocolo do servidor RemoteID da Certisign.
//!
//! Não está sob nosso controle: tem de sair igual ao do RemoteID-linux v0.3.2,
//! que foi reconstruído do app oficial de macOS e confirmado com conta real. A
//! paridade é provada contra o código de lá por `tests/paridade.rs`, com as
//! fixtures que o `paridade/` grava rodando o antigo.
//!
//! Só funções puras: montam a requisição e leem a resposta. Quem fala com a
//! rede é o motor.

pub mod algoritmo;
pub mod canonica;
pub mod classificacao;
pub mod requisicao;
pub mod resposta;

pub use algoritmo::Algoritmo;
pub use requisicao::{Metodo, Requisicao};

pub const REMOTEID_URL: &str = "https://remoteidcertisign.com.br";
pub const CERTINEXT_URL: &str = "https://certinext.certisign.com.br";
pub const CERTINEXT_BASE: &str = "/CertisignerServices";

/// O User-Agent do app oficial, para não destoar no servidor.
pub const USER_AGENT: &str = "desktopID/2.2.0.1";

/// O que vai em `nomeAplicacaoDesktop`. O servidor aceita qualquer nome, e um
/// reconhecível ajuda o titular a identificar a sessão.
pub const NOME_APLICACAO: &str = "RemoteID-linux";

/// Onde estão os dois serviços. Os testes trocam pelo servidor falso.
#[derive(Debug, Clone)]
pub struct Servidor {
    pub remoteid: String,
    pub certinext: String,
}

impl Servidor {
    pub fn producao() -> Servidor {
        Servidor {
            remoteid: REMOTEID_URL.into(),
            certinext: CERTINEXT_URL.into(),
        }
    }
}

/// Um certificado da carteira. O `keyName` é `<serial>;<emissor>`, e o
/// emissor pode ter `;` dentro: só o primeiro separa.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Certificado {
    pub key_name: String,
    pub serial_number: String,
    pub issue: String,
    /// O DER do certificado em base64, quando a carteira o traz.
    pub base64: Option<String>,
}

impl Certificado {
    pub fn do_key_name(key_name: &str, base64: Option<String>) -> Option<Certificado> {
        let (serial, emissor) = key_name.split_once(';')?;
        Some(Certificado {
            key_name: key_name.into(),
            serial_number: serial.into(),
            issue: emissor.into(),
            base64,
        })
    }

    /// O que identifica o certificado no estado. É o `keyName` refeito dos
    /// dois campos, para que um espaço a mais vindo do servidor não descarte
    /// a sessão em cache.
    pub fn chave(&self) -> String {
        format!("{};{}", self.serial_number, self.issue)
    }
}
