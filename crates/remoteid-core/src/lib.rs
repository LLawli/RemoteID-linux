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

pub mod authmode;
pub mod canonical;
pub mod config;
pub mod crypto;
pub mod diag;
pub mod engine;
pub mod error;
pub mod http;
pub mod pkcs7;
pub mod protocol;
pub mod state;

pub use authmode::{Estado as EstadoAuth, Fatores, Modo};
pub use engine::{Motor, Opcoes};
pub use error::{Error, Origem, Result, ServerError};
