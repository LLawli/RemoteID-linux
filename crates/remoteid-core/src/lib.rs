//! Motor do certificado em nuvem RemoteID (Certisign) para Linux.
//!
//! A Certisign distribui o app "RemoteID" só para macOS e Windows. Este crate
//! reimplementa o protocolo que aquele app fala, para que o certificado em
//! nuvem possa ser usado no Linux. O protocolo foi reconstruído por
//! decompilação do binário oficial de macOS e confirmado ao vivo contra o
//! servidor com uma conta real.
//!
//! # Por onde começar
//!
//! - [`engine::Motor`] é a API: `login` → `registrar` → `carteira` →
//!   `assinar_digest`.
//! - [`canonical`] explica a assinatura que autentica cada requisição, que é a
//!   parte não óbvia do protocolo.
//! - [`authmode`] explica como o app oficial escolhe entre pin+otp e push, e
//!   por que as duas coisas nunca andam juntas.
//! - [`diag`] é o log detalhado em arquivo, base da futura feature de bug report.
//!
//! # O que o motor devolve
//!
//! [`engine::Motor::assinar_digest`] entrega o bloco RSA **cru** de 256 bytes,
//! não um PKCS#7. É de propósito: é o contrato que o `C_Sign` do PKCS#11 tem de
//! cumprir, e é sobre ele que um assinador de PDF monta o CAdES.


pub mod canonical;
pub mod config;
pub mod diag;
pub mod engine;
pub mod http;
pub mod pkcs7;
pub mod protocol;

mod chave;
mod estado_fs;

// Domínio puro extraído para crates próprios (Fase 1). O core os re-exporta com
// os nomes de módulo antigos para não quebrar os consumidores enquanto a borda
// não passa a depender diretamente dos domínios.
pub use remoteid_tipos as error;
pub use remoteid_autorizacao as authmode;

/// Fachada de criptografia: as primitivas puras de [`remoteid_cripto`] mais os
/// helpers de I/O da chave ([`crate::chave`], futuro adaptador `chave-pem`). O
/// nome `crypto` é mantido para os consumidores atuais.
pub mod crypto {
    pub use crate::chave::{carregar, carregar_ou_gerar};
    pub use remoteid_cripto::*;
}

/// Fachada de estado: os tipos e a política puros de [`remoteid_estado`] mais os
/// helpers de I/O ([`crate::estado_fs`]: diretórios, `carregar`/`salvar`, futuro
/// adaptador `store-json`). O nome `state` é mantido para os consumidores.
pub mod state {
    pub use crate::estado_fs::{
        carregar, caminho_chave, caminho_estado, dir_dados, dir_diag, em_teste, salvar, DIR_TESTE,
    };
    pub use remoteid_estado::*;
}

pub use authmode::{Estado as EstadoAuth, Fatores, Modo};
pub use engine::{Motor, Opcoes};
pub use error::{Error, Origem, Result, ServerError};
