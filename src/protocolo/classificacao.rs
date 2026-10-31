//! O que cada mensagem de erro do servidor quer dizer, e de quem é a vez de
//! agir.
//!
//! A busca é por fragmento, em minúsculas, na mensagem somada ao corpo cru. A
//! ordem da tabela decide quando dois fragmentos casam: "pin ou e-token
//! incorreto" vem antes de "e-token", porque a dica de lá ("o servidor aceitou
//! o PIN") seria falsa aqui. Fontes: as runs reais do RemoteID-linux e as
//! literais de erro do binário oficial.

/// De quem é a vez de agir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origem {
    /// A pessoa corrige: credencial, PIN, OTP.
    Usuario,
    /// O corpo que este cliente montou está errado.
    Cliente,
    /// Infraestrutura da Certisign: não adianta mexer no pedido nem na conta.
    Servidor,
    Desconhecida,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regra {
    pub fragmento: &'static str,
    pub origem: Origem,
    pub dica: &'static str,
}

const fn regra(fragmento: &'static str, origem: Origem, dica: &'static str) -> Regra {
    Regra {
        fragmento,
        origem,
        dica,
    }
}

pub const REGRAS: &[Regra] = &[
    regra(
        "senha inv",
        Origem::Usuario,
        "E-mail ou senha do RemoteID incorretos.",
    ),
    regra(
        "usuariosenhainvalido",
        Origem::Usuario,
        "E-mail ou senha do RemoteID incorretos.",
    ),
    // Recusa de fator medida em campo em 29/09/2026: o servidor não diz se o
    // errado é o PIN ou o OTP.
    regra(
        "pin ou e-token incorreto",
        Origem::Usuario,
        "PIN ou código do autenticador recusado. Confira o PIN e use um código novo.",
    ),
    regra(
        "informe o pin",
        Origem::Usuario,
        "O servidor exigiu o PIN: a sessão precisa do PIN e do código juntos.",
    ),
    regra(
        "e-token",
        Origem::Usuario,
        "O servidor exigiu o código do autenticador: a sessão precisa do PIN e do código juntos.",
    ),
    regra(
        "não existe autorização válida",
        Origem::Usuario,
        "PIN ou código inválido ou vencido. Gere um código novo.",
    ),
    regra(
        "código de autorização inválida",
        Origem::Usuario,
        "Credencial recusada. Com PIN e código certos, a suspeita é a assinatura do Bearer.",
    ),
    regra(
        "tempo esgotado",
        Origem::Usuario,
        "O tempo de aprovação acabou. Tente de novo.",
    ),
    regra(
        "sem chave pública",
        Origem::Cliente,
        "Faltou a chave pública no registro.",
    ),
    regra(
        "domainnameleftblank",
        Origem::Cliente,
        "Faltou o domínio de rede (o nome da máquina) no registro.",
    ),
    regra(
        "não suportado",
        Origem::Cliente,
        "O servidor recusou o formato do pedido.",
    ),
    regra(
        "constraintviolation",
        Origem::Cliente,
        "O servidor não gravou um campo do pedido (provavelmente a chave pública ou o domínio).",
    ),
    regra(
        "could not execute statement",
        Origem::Cliente,
        "O banco do servidor recusou um campo do pedido.",
    ),
    regra(
        "dataintegrityviolation",
        Origem::Cliente,
        "O banco do servidor recusou um campo do pedido.",
    ),
    regra(
        "illegal base64",
        Origem::Cliente,
        "O Authorization levou o JWT do login onde vai a assinatura da chave da instalação.",
    ),
    regra(
        "apns",
        Origem::Servidor,
        "O servidor não achou celular para a aprovação.",
    ),
    regra(
        "erro ao enviar push",
        Origem::Servidor,
        "O servidor não conseguiu enviar a aprovação ao celular.",
    ),
    regra(
        "offline",
        Origem::Servidor,
        "O serviço da Certisign está fora do ar. Tente mais tarde.",
    ),
    regra(
        "internal server error",
        Origem::Servidor,
        "Erro interno no servidor da Certisign.",
    ),
    regra(
        "problema ao criar",
        Origem::Servidor,
        "O servidor recusou o registro desta máquina.",
    ),
    regra(
        "abertura de sessão não realizada",
        Origem::Servidor,
        "O servidor não abriu a sessão de assinatura.",
    ),
];

/// A primeira regra que casa com a mensagem ou com o corpo.
pub fn classificar(mensagem: &str, corpo: &str) -> Option<&'static Regra> {
    let alvo = format!("{mensagem} {corpo}").to_lowercase();
    REGRAS.iter().find(|r| alvo.contains(r.fragmento))
}

/// Fragmentos que dizem que o `sessionToken` enviado não vale mais. Só eles
/// autorizam descartar a sessão em cache e pedir PIN e OTP de novo; errar para
/// o lado do sim gastaria um OTP para receber o mesmo erro.
const SESSAO_INVALIDA: &[&str] = &[
    "não existe autorização válida",
    "session",
    "sessão",
    "token expirado",
    "token inválido",
];

pub fn falha_de_sessao(mensagem: &str, corpo: &str) -> bool {
    let alvo = format!("{mensagem} {corpo}").to_lowercase();
    SESSAO_INVALIDA.iter().any(|f| alvo.contains(f))
}
