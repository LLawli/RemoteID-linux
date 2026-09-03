//! Método de autorização: o que o app oficial realmente faz.
//!
//! Este módulo existe porque o harness em Python errava aqui. Ele procurava um
//! campo `AuthorizationMode` na resposta da carteira, não achava, e reportava
//! "método de autorização da conta: [ ]". A decompilação mostra por quê: **esse
//! campo nunca vem do servidor**.
//!
//! # O que o binário diz (Ghidra, binário Mach-O de macOS 2.2.0.1)
//!
//! ## 1. `AuthorizationMode` é estado LOCAL, não resposta do servidor
//!
//! A literal `AuthorizationMode` (UTF-32LE em `0x1005dc6fc`) tem exatamente
//! dois xrefs, e os dois são persistência do `identity.xml`:
//!
//! | função | papel |
//! |---|---|
//! | `FUN_100064bec` | lê o XML para a struct `RemoteIDInstallation` |
//! | `FUN_100064f52` | escreve a struct de volta no XML |
//!
//! O nó `RemoteIDInstallation` é `TargetUrl, UserID, UserName, OrganizationID,
//! OrganizationName, DesktopCode, AuthorizationMode, Wallet`, e o campo mora no
//! offset `0x90` da struct. Nenhum parser de JSON toca nele.
//!
//! ## 2. Quem grava o valor é o `statusCelular`, e ele grava sempre `local`
//!
//! `FUN_10006739a` trata a resposta do `statusCelular`. No disassembly:
//!
//! ```text
//! 1000678ab  LEA  RSI,[0x1002ac173]   ; "usuarioPossuiCodigoPush"
//! 1000678b9  CALL FUN_1000366f0       ; json["usuarioPossuiCodigoPush"]
//! 1000678c1  CALL FUN_100035570       ; asBool  -> resultado DESCARTADO
//! 1000678c6  ADD  R15,0x90            ; &installation->AuthorizationMode
//! 1000678cd  LEA  RSI,[0x1005dcb48]   ; L"local"
//! 1000678d7  CALL assign              ; AuthorizationMode = "local"
//! ```
//!
//! Não há ternário: o booleano é lido, convertido e jogado fora. O modo vira
//! `local` incondicionalmente. `usuarioPossuiCodigoPush` é, nesta versão,
//! informação de capacidade sem efeito no fluxo.
//!
//! ## 3. O modo vira um ESTADO, e o estado escolhe o construtor
//!
//! `FUN_1000587de` (método virtual) traduz a string do modo num inteiro:
//!
//! | `AuthorizationMode` | estado |
//! |---|---|
//! | `push` | 1 (`PROMPT_FOR_PUSH`) |
//! | `local` | 2 |
//! | `mobileId` | 0 |
//! | **qualquer outro, incluindo `otp` e `pin`** | 2 |
//!
//! `otp` e `pin` não são comparados em lugar nenhum: caem no mesmo estado 2 que
//! `local`. Só três valores são reconhecidos de verdade.
//!
//! ## 4. Os dois caminhos são mutuamente exclusivos por construção
//!
//! Ambos constroem a MESMA classe (`PasswordAndOtpAuthentication`, ponteiro de
//! vtable `0x100623a08`, objeto de `0x88` bytes), mas por construtores
//! diferentes, cada um exigindo o seu estado:
//!
//! | | `FUN_100058b9e` (pin+otp) | `FUN_100058de6` (push) |
//! |---|---|---|
//! | estado exigido | 2, senão lança `NO_USER_INTERACTION: invalid state` | 1, senão lança `state must be: PROMPT_FOR_PUSH` |
//! | `desktopCode` (0x08) | preenchido | preenchido |
//! | `pin` (0x38) | do dicionário, chave `pin` | **fica vazio** |
//! | `otp` (0x50) | do dicionário, chave `otp` | **fica vazio** |
//! | `nomeAplicacaoDesktop` (0x68) | **fica vazio** | preenchido |
//! | `push` (0x80) | `false` | `true` |
//!
//! **Não existe "push + pin" no app oficial.** O objeto é zerado na alocação e
//! cada construtor só preenche os campos do seu caminho; o estado impede que um
//! caminho use o construtor do outro. Quem mandar `push:true` junto com um PIN
//! está inventando uma combinação que o cliente oficial nunca emite, e o
//! servidor nunca viu.
//!
//! ## 5. Não há polling no caminho push do RemoteID
//!
//! `openSession` (`FUN_1000763a2`) monta o corpo, faz UM POST e trata a
//! resposta: token, ou `status:false` com a mensagem, ou
//! `"Abertura de sessão não realizada (<http>): <message>"`. Não há laço de
//! espera. E as únicas oito rotas `/api/...` do binário não incluem nada de
//! polling (ver [`crate::config`]). Ou seja: no push do RemoteID, ou o servidor
//! segura a requisição até o celular aprovar, ou ela falha na hora. O
//! `create → requestAuthorization → isAuthorized → push → isDone`, esse sim com
//! polling, é do serviço ANTIGO `/desktop`, em outro host.
//!
//! # Consequência para este cliente
//!
//! O modo é uma **política local**, não uma descoberta. O padrão correto é
//! [`Modo::Local`] (estado 2, pin+otp), que é onde o app oficial sempre cai. O
//! push fica atrás de escolha explícita do usuário, sem testador que o exercite.

use std::fmt;
use std::str::FromStr;

/// Valor persistido em `AuthorizationMode` no `identity.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modo {
    /// `push`: aprovação no celular. Estado 1.
    Push,
    /// `local`: é o que o app oficial sempre grava. Estado 2 (pin+otp).
    Local,
    /// `mobileId`: outra estratégia de assinatura, fora do RemoteID. Estado 0.
    MobileId,
    /// `otp` / `pin` / qualquer outro: o binário não os reconhece e todos caem
    /// no estado 2, igual a `local`. Preservamos o texto para o identity.xml.
    Outro(String),
}

impl Modo {
    /// Estado interno, exatamente como `FUN_1000587de` traduz.
    pub fn estado(&self) -> Estado {
        match self {
            Modo::Push => Estado::PromptForPush,
            Modo::Local => Estado::Interativo,
            Modo::MobileId => Estado::MobileId,
            // O binário compara só contra push/local/mobileId; o resto (otp,
            // pin, lixo) cai no default, que é o mesmo estado do `local`.
            Modo::Outro(_) => Estado::Interativo,
        }
    }

    pub fn como_str(&self) -> &str {
        match self {
            Modo::Push => "push",
            Modo::Local => "local",
            Modo::MobileId => "mobileId",
            Modo::Outro(s) => s,
        }
    }
}

impl Default for Modo {
    /// `local`: o valor que o `statusCelular` do app oficial sempre grava.
    fn default() -> Self {
        Modo::Local
    }
}

impl FromStr for Modo {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // O binário compara sem normalizar caixa; mantemos isso, mas aceitamos
        // as grafias que o usuário digita na linha de comando.
        Ok(match s {
            "push" => Modo::Push,
            "local" => Modo::Local,
            "mobileId" | "mobileid" => Modo::MobileId,
            outro => Modo::Outro(outro.to_string()),
        })
    }
}

impl fmt::Display for Modo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.como_str())
    }
}

/// Estado interno que decide qual construtor de autenticação o app usa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Estado {
    /// 0 — estratégia MobileID, que não passa pelo RemoteID.
    MobileId = 0,
    /// 1 — `PROMPT_FOR_PUSH`: só `push:true`, sem pin nem otp.
    PromptForPush = 1,
    /// 2 — o caminho interativo: `pin` + `otp` juntos, `push:false`.
    Interativo = 2,
}

/// Fatores a mandar no `tokensessao`, já no formato que o construtor
/// correspondente do app produz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fatores {
    /// Estado 2. O servidor exige os DOIS no mesmo request: mandar só um
    /// devolve "Informe o Pin" ou "Informe o e-Token(Otp)".
    PinOtp { pin: String, otp: String },
    /// Estado 1. `pin` e `otp` seguem vazios, como no construtor do app.
    Push,
}

impl Fatores {
    pub fn estado(&self) -> Estado {
        match self {
            Fatores::PinOtp { .. } => Estado::Interativo,
            Fatores::Push => Estado::PromptForPush,
        }
    }

    /// Recusa a combinação que o app oficial não consegue emitir.
    ///
    /// Não é preciosismo: os construtores lançam exceção quando o estado não
    /// bate, então um `push:true` com PIN preenchido é um payload que o
    /// servidor nunca recebeu de um cliente oficial.
    pub fn compativel_com(&self, modo: &Modo) -> Result<(), String> {
        if self.estado() == modo.estado() {
            return Ok(());
        }
        Err(format!(
            "modo '{}' está no estado {:?}, mas os fatores pedem o estado {:?}. \
             No app oficial os construtores lançam exceção nesse caso \
             (`state must be: PROMPT_FOR_PUSH` / `NO_USER_INTERACTION: invalid \
             state`), e push nunca anda junto de pin/otp.",
            modo,
            modo.estado(),
            self.estado(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tres_modos_reconhecidos_e_o_resto_cai_no_estado_2() {
        assert_eq!(Modo::Push.estado(), Estado::PromptForPush);
        assert_eq!(Modo::Local.estado(), Estado::Interativo);
        assert_eq!(Modo::MobileId.estado(), Estado::MobileId);
        // otp e pin NÃO são comparados no binário: caem no default.
        assert_eq!("otp".parse::<Modo>().unwrap().estado(), Estado::Interativo);
        assert_eq!("pin".parse::<Modo>().unwrap().estado(), Estado::Interativo);
        assert_eq!("bloop".parse::<Modo>().unwrap().estado(), Estado::Interativo);
    }

    #[test]
    fn o_padrao_e_o_que_o_statuscelular_grava() {
        // FUN_10006739a atribui L"local" incondicionalmente.
        assert_eq!(Modo::default(), Modo::Local);
        assert_eq!(Modo::default().estado(), Estado::Interativo);
    }

    #[test]
    fn push_com_pin_e_recusado() {
        let fatores = Fatores::PinOtp { pin: "1234".into(), otp: "999999".into() };
        assert!(fatores.compativel_com(&Modo::Push).is_err());
        assert!(Fatores::Push.compativel_com(&Modo::Local).is_err());
    }

    #[test]
    fn cada_fator_casa_com_o_seu_estado() {
        let pinotp = Fatores::PinOtp { pin: "1".into(), otp: "2".into() };
        assert!(pinotp.compativel_com(&Modo::Local).is_ok());
        assert!(pinotp.compativel_com(&"otp".parse().unwrap()).is_ok());
        assert!(Fatores::Push.compativel_com(&Modo::Push).is_ok());
    }

    #[test]
    fn preserva_o_texto_original_para_o_identity_xml() {
        assert_eq!("otp".parse::<Modo>().unwrap().como_str(), "otp");
        assert_eq!(Modo::Local.como_str(), "local");
    }
}
