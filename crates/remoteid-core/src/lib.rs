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
//!
//! # O que ficou aqui, e o que saiu
//!
//! Depois da Fase 1 este crate é a **casca imperativa**: o [`engine`]
//! (orquestração), o [`http`] (transporte) e o [`diag`] (log). O domínio puro
//! foi extraído para crates próprios ([`remoteid_tipos`], [`remoteid_cripto`],
//! [`remoteid_autorizacao`], [`remoteid_estado`], [`remoteid_assinatura`],
//! [`remoteid_protocolo_servidor`]); o core os re-exporta com os nomes de módulo
//! antigos (`error`, `crypto`, `authmode`, `pkcs7`, `state`, `canonical`,
//! `config`, `protocol`) para os consumidores não mudarem enquanto a borda não
//! depende dos domínios diretamente. O I/O de disco vive nas fachadas
//! [`crate::crypto`] e [`crate::state`] (sementes dos adaptadores da Fase 2).

pub mod engine;


mod chave;
mod estado_fs;

pub use remoteid_diag_jsonl as diag;
pub use remoteid_http as http;
pub use remoteid_tipos as error;
pub use remoteid_autorizacao as authmode;
pub use remoteid_assinatura as pkcs7;
pub use remoteid_protocolo_servidor::{canonical, config, protocol, resposta};

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
pub use engine::{Dependencias, Motor, Opcoes};
pub use error::{Error, Origem, Result, ServerError};
