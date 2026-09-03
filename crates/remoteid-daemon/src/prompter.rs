//! Como o daemon obtém PIN e OTP quando o cache falha.
//!
//! O trait [`Prompter`] existe para que o esqueleto do daemon seja completável
//! HOJE, sem GTK, e que os testes de integração exercitem o fluxo otimista
//! (cache hit, invalidação, retry) com fatores enlatados. A implementação com
//! GTK (`GtkPrompter`) vive em outro módulo, num commit separado — a decisão
//! do dia 03/09/2026 é que o daemon linka GTK direto ("Eixo 2 = A"), sem
//! spawn de helper.
//!
//! A implementação de teste [`FatoresFixos`] devolve um par pré-configurado.
//! Nenhuma implementação lê PIN/OTP do ambiente ou de arquivo: PIN e OTP são
//! sensíveis e só entram por interação humana ou por injeção explícita em
//! teste.

use remoteid_core::authmode::Fatores;
use remoteid_core::error::{Error, Result};

/// Fonte dos fatores quando o cache do `sessionToken` não bastar.
///
/// Um único método porque, na prática, o daemon precisa dos DOIS
/// simultaneamente (o `tokensessao` do RemoteID exige pin + otp no mesmo
/// request — armadilha registrada em `docs/PAYLOADS.md`). Separar em dois
/// prompts convidaria a UI a mostrar as duas coisas em telas diferentes e
/// gastar OTP a mais.
pub trait Prompter: Send + Sync {
    /// Pede PIN+OTP ao usuário. Devolve [`Fatores::PinOtp`] se aprovado, ou
    /// `Err(Error::Uso("cancelado ..."))` se o usuário fechou o diálogo — o
    /// [`crate::servico::Servico`] traduz esse erro para [`crate::protocolo::CodigoErro::Cancelado`].
    fn pedir_pin_otp(&self, contexto: &Contexto) -> Result<Fatores>;
}

/// O que a UI precisa saber para escrever um diálogo útil.
#[derive(Debug, Clone)]
pub struct Contexto {
    /// Nome bruto do hospedeiro (`comm` do processo cliente), quando conhecido.
    pub hospedeiro: Option<String>,
    /// Common Name do certificado ativo — a UI mostra "Assinar como <CN>".
    pub titular: Option<String>,
}

/// Prompter de teste: devolve fatores fixos, ou o erro pré-configurado.
///
/// Uma flag de "cancelar" para exercitar o caminho de cancelamento sem
/// depender de mensagens específicas de erro.
pub struct FatoresFixos {
    pub pin: String,
    pub otp: String,
    pub cancelar: bool,
}

impl FatoresFixos {
    pub fn novo(pin: impl Into<String>, otp: impl Into<String>) -> Self {
        FatoresFixos { pin: pin.into(), otp: otp.into(), cancelar: false }
    }
}

impl Prompter for FatoresFixos {
    fn pedir_pin_otp(&self, _: &Contexto) -> Result<Fatores> {
        if self.cancelar {
            return Err(Error::uso("cancelado pelo usuário no diálogo"));
        }
        Ok(Fatores::PinOtp { pin: self.pin.clone(), otp: self.otp.clone() })
    }
}
