//! Endpoints e mensagens conhecidas, extraídos do app oficial de macOS 2.2.0.1.
//!
//! As duas bases vêm de
//! `/Library/Application Support/desktopID/applicationConfig-2.properties`,
//! instalado pelo subpacote `br.com.certisign.ApplicationConfig2`:
//!
//! ```text
//! certinext.url       = https://certinext.certisign.com.br
//! certinext.base.name = /CertisignerServices
//! remoteid.url        = remoteidcertisign.com.br
//! ```
//!
//! Os caminhos são as literais `std::wstring` (UTF-32LE) do binário
//! `desktopID.app/Contents/MacOS/desktopID`. A lista do RemoteID abaixo é
//! COMPLETA: são as únicas oito rotas `/api/...` presentes no binário. Isso
//! importa para o caminho push, porque prova que não existe endpoint de
//! polling ("isDone") do lado do RemoteID — ver [`crate::authmode`].

use crate::error::Origem;

pub const CERTINEXT_URL: &str = "https://certinext.certisign.com.br";
pub const CERTINEXT_BASE: &str = "/CertisignerServices";
pub const REMOTEID_URL: &str = "https://remoteidcertisign.com.br";

/// User-Agent do app oficial. Mantido igual para não destoar no servidor.
pub const USER_AGENT: &str = "desktopID/2.2.0.1";

/// Nome que este cliente manda em `nomeAplicacaoDesktop` no caminho push.
pub const NOME_APLICACAO: &str = "RemoteID-linux";

// --- serviço do RemoteID (certinext + /CertisignerServices/desktop) -------
// É o fluxo ANTIGO, de push com pareamento no celular. Mantido para o caminho
// push e para diagnóstico; a assinatura em si vai pelo RemoteID.

pub const DESKTOP_PREFIX: &str = "/desktop";
pub const EP_CREATE: &str = "/create";
pub const EP_PUSH: &str = "/push/";
pub const EP_REQUEST_AUTHORIZATION: &str = "/requestAuthorization/";
pub const EP_IS_AUTHORIZED: &str = "/isAuthorized/";
pub const EP_CANCEL_AUTHORIZATION: &str = "/cancelAuthorization/";
pub const EP_IS_DONE: &str = "/isDone/";
pub const EP_LIST_CERTIFICATES: &str = "/listCertificates/";
pub const EP_LIST_HIERARCHIES: &str = "/listHierarchies";
pub const EP_MAINTENANCE_DEVICES: &str = "/maintenanceDevices/";

// --- API do RemoteID (remoteidcertisign.com.br) ---------------------------

pub const EP_RID_LOGIN: &str = "/api/manager/usuarios/login/usrsenha";
pub const EP_RID_SESSION_TOKEN: &str = "/api/signature/tokensessao";
pub const EP_RID_REQUEST_HASH: &str = "/api/signature/requestHashSessionSignature";

/// `/api/manager/desktopid/{codigoDesktop}/carteira`
pub fn ep_carteira(codigo_desktop: &str) -> String {
    format!("/api/manager/desktopid/{codigo_desktop}/carteira")
}

/// `/api/manager/desktopid/{codigoDesktop}/carteira/invalida`
pub fn ep_carteira_invalida(codigo_desktop: &str) -> String {
    format!("/api/manager/desktopid/{codigo_desktop}/carteira/invalida")
}

/// `/api/manager/desktopid/{codigoDesktop}/statusCelular`
pub fn ep_status_celular(codigo_desktop: &str) -> String {
    format!("/api/manager/desktopid/{codigo_desktop}/statusCelular")
}

/// `/api/manager/desktopid/usuario/{userId}/organizacao/{orgId}`
pub fn ep_registrar_desktop(user_id: i64, org_id: i64) -> String {
    format!("/api/manager/desktopid/usuario/{user_id}/organizacao/{org_id}")
}

/// Mensagens conhecidas do backend (e do cliente oficial) e o que fazer.
///
/// A busca é por SUBSTRING em minúsculas, na `message` do corpo somada ao corpo
/// cru. Fontes: mensagens observadas ao vivo nas runs do testador e as literais
/// de erro extraídas do binário oficial.
pub const SERVER_HINTS: &[(&str, Origem, &str)] = &[
    ("senha inv", Origem::Usuario,
     "Credenciais do RemoteID incorretas: confira e-mail e senha (a senha do \
      RemoteID, não a de outro portal)."),
    ("usuariosenhainvalido", Origem::Usuario,
     "Credenciais do RemoteID incorretas."),
    ("informe o pin", Origem::Usuario,
     "O servidor exigiu o PIN do certificado. O tokensessao precisa dos DOIS \
      fatores juntos (pin + otp) no mesmo request."),
    ("e-token", Origem::Usuario,
     "O servidor aceitou o PIN e agora exige o código do autenticador: o \
      tokensessao precisa dos DOIS fatores juntos (pin + otp)."),
    ("não existe autorização válida", Origem::Usuario,
     "OTP/PIN inválido ou expirado, ou o desktopCode/certificado não bateu. \
      Gere um novo código e confirme o certificado."),
    ("código de autorização inválida", Origem::Usuario,
     "Credencial recusada. Se pin e otp estão certos e recentes, suspeite da \
      ASSINATURA do Bearer (canonicalização), não do fator."),
    ("tempo esgotado", Origem::Usuario,
     "Tempo de aprovação esgotado; refaça e aprove."),
    ("sem chave pública", Origem::Cliente,
     "chavePublica faltando ou vazia no payload."),
    ("domainnameleftblank", Origem::Cliente,
     "dominioRede vazio (o cliente deve preencher com o hostname)."),
    ("não suportado", Origem::Cliente,
     "O servidor recusou o formato do payload."),
    ("constraintviolation", Origem::Cliente,
     "Violação de constraint no banco: algum campo foi enviado em formato que \
      o servidor não grava (provável chavePublica ou dominioRede)."),
    ("could not execute statement", Origem::Cliente,
     "Insert rejeitado pelo banco; ver o campo malformado no payload."),
    ("dataintegrityviolation", Origem::Cliente,
     "Dado rejeitado pelo banco (formato ou nulo)."),
    ("illegal base64", Origem::Cliente,
     "O servidor tentou base64-decodar o Bearer e falhou: você mandou o JWT do \
      login onde vai a ASSINATURA da chave da instalação."),
    ("apns", Origem::Servidor,
     "O servidor não achou celular para o push. Use pin+otp."),
    ("erro ao enviar push", Origem::Servidor,
     "O servidor não conseguiu enviar o push."),
    ("offline", Origem::Servidor,
     "Serviço da Certisign indisponível; tente mais tarde."),
    ("internal server error", Origem::Servidor,
     "Erro interno do backend da Certisign."),
    ("problema ao criar", Origem::Servidor,
     "Falha ao registrar (o servidor recusou)."),
    ("abertura de sessão não realizada", Origem::Servidor,
     "Falha ao abrir a sessão de assinatura."),
];

/// Classifica a mensagem de erro do servidor.
pub fn classificar(mensagem: &str, corpo: &str) -> (Origem, Option<&'static str>) {
    let alvo = format!("{mensagem} {corpo}").to_lowercase();
    for (frag, origem, hint) in SERVER_HINTS {
        if alvo.contains(frag) {
            return (*origem, Some(*hint));
        }
    }
    (Origem::Desconhecida, None)
}

/// Fragmentos de mensagem que o servidor devolve quando o `sessionToken`
/// enviado no `requestHashSessionSignature` já não vale (expirou, foi
/// revogado, ou nunca existiu deste lado). São o gatilho do retry silencioso
/// do fluxo otimista: o motor invalida a entrada de cache daquele
/// certificado e reemite com PIN+OTP.
///
/// A lista é conservadora de propósito. "Não existe autorização válida para
/// este token" foi observada ao vivo no `tokensessao` quando PIN/OTP não
/// bateram, mas a MESMA mensagem também aparece no `requestHash` quando o
/// `sessionToken` já não vale — como este classificador só é chamado no
/// caminho de retry do requestHash, ambos os casos convergem para "reemitir".
/// Novos fragmentos entram aqui depois que a medição do TTL revelar as
/// mensagens exatas de expiração.
pub const SESSAO_INVALIDA_HINTS: &[&str] = &[
    "não existe autorização válida",
    "session",
    "sessão",
    "token expirado",
    "token inválido",
];

/// `true` se a mensagem sinaliza que o `sessionToken` já não serve e faz
/// sentido pedir PIN+OTP e reemitir.
pub fn e_falha_de_sessao(mensagem: &str, corpo: &str) -> bool {
    let alvo = format!("{mensagem} {corpo}").to_lowercase();
    SESSAO_INVALIDA_HINTS.iter().any(|f| alvo.contains(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifica_as_mensagens_das_runs_reais() {
        // As duas que o tokensessao devolveu ao vivo em 02/09/2026.
        assert_eq!(classificar("Informe o Pin", "").0, Origem::Usuario);
        assert_eq!(classificar("Informe o e-Token(Otp)", "").0, Origem::Usuario);
        // A que apareceu antes de descobrir a auth por assinatura.
        assert_eq!(
            classificar("Illegal base64 character 2e", "").0,
            Origem::Cliente
        );
        // A do push quebrado no backend.
        assert_eq!(classificar("Error sending apns server", "").0, Origem::Servidor);
    }

    #[test]
    fn mensagem_desconhecida_nao_inventa_origem() {
        let (origem, hint) = classificar("bloop", "");
        assert_eq!(origem, Origem::Desconhecida);
        assert!(hint.is_none());
    }

    #[test]
    fn monta_os_paths_com_codigo_desktop_nao_com_cpf() {
        // Armadilha já mapeada: carteira e statusCelular usam o codigoDesktop
        // no path, não o CPF.
        assert_eq!(
            ep_carteira("4d1f71d2-c20b-44d0-9bb0-5629015f21e8"),
            "/api/manager/desktopid/4d1f71d2-c20b-44d0-9bb0-5629015f21e8/carteira"
        );
        assert_eq!(
            ep_registrar_desktop(327989, 0),
            "/api/manager/desktopid/usuario/327989/organizacao/0"
        );
    }
}
