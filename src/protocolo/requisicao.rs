//! Cada requisição que o cliente faz, pronta para o transporte: método, URL,
//! corpo nos bytes exatos e o `Authorization`.
//!
//! O corpo sai do `serde_json` sem `preserve_order`, então em ordem alfabética
//! de chave, como o jsoncpp do app oficial. A ordem no fio é cosmética (o
//! `Bearer` assina a canônica, que ordena por conta própria), mas a paridade é
//! byte a byte mesmo assim.

use serde_json::{Value, json};

use super::canonica::canonica;
use super::{Algoritmo, CERTINEXT_BASE, Certificado, NOME_APLICACAO, Servidor, USER_AGENT};
use crate::cripto::{ChaveInstalacao, b64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metodo {
    Get,
    Post,
}

impl Metodo {
    pub fn nome(self) -> &'static str {
        match self {
            Metodo::Get => "GET",
            Metodo::Post => "POST",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requisicao {
    pub metodo: Metodo,
    pub url: String,
    pub corpo: Option<String>,
    /// O valor inteiro do cabeçalho `Authorization`.
    pub autorizacao: Option<String>,
}

impl Requisicao {
    /// Os cabeçalhos que o protocolo define. O transporte acrescenta os dele
    /// (tamanho, compressão).
    pub fn cabecalhos(&self) -> Vec<(&'static str, &str)> {
        let mut cabecalhos = vec![("accept", "application/json"), ("user-agent", USER_AGENT)];
        if self.corpo.is_some() {
            cabecalhos.push(("content-type", "application/json"));
        }
        if let Some(a) = &self.autorizacao {
            cabecalhos.push(("authorization", a));
        }
        cabecalhos
    }
}

fn post(url: String, corpo: &Value, autorizacao: Option<String>) -> Requisicao {
    Requisicao {
        metodo: Metodo::Post,
        url,
        corpo: Some(corpo.to_string()),
        autorizacao,
    }
}

/// Os endpoints de operação não usam o JWT do login: o `Bearer` é a
/// assinatura da canônica do corpo com a chave da instalação.
fn operacao(
    servidor: &Servidor,
    caminho: &str,
    corpo: Value,
    chave: &ChaveInstalacao,
) -> Requisicao {
    let bearer = format!("Bearer {}", chave.bearer(&canonica(&corpo)));
    post(url(&servidor.remoteid, caminho), &corpo, Some(bearer))
}

fn url(base: &str, caminho: &str) -> String {
    format!("{}{caminho}", base.trim_end_matches('/'))
}

/// O anti-replay de `carteira` e `statusCelular`: o corpo é só o instante,
/// como string, e o `Bearer` o cobre. Corpo vazio dá 400.
fn momento(agora: u64) -> Value {
    json!({ "momento": agora.to_string() })
}

/// A única rota que responde sem estado nenhum: serve de teste de conexão.
pub fn hierarquias(servidor: &Servidor) -> Requisicao {
    Requisicao {
        metodo: Metodo::Get,
        url: url(
            &servidor.certinext,
            &format!("{CERTINEXT_BASE}/desktop/listHierarchies"),
        ),
        corpo: None,
        autorizacao: None,
    }
}

/// A chave é `email`, não `usuario` nem `login`.
pub fn login(servidor: &Servidor, email: &str, senha: &str) -> Requisicao {
    let corpo = json!({ "email": email, "senha": senha });
    post(
        url(&servidor.remoteid, "/api/manager/usuarios/login/usrsenha"),
        &corpo,
        None,
    )
}

/// O que identifica esta máquina no registro.
pub struct Maquina<'a> {
    pub nome: &'a str,
    pub usuario_local: &'a str,
    /// O nome da máquina. Vazio, o servidor responde `DomainNameLeftBlank`.
    pub dominio_rede: &'a str,
}

/// O único passo, além do login, que usa o JWT no `Authorization`.
pub fn registrar(
    servidor: &Servidor,
    jwt: &str,
    user_id: i64,
    organizacao_id: i64,
    maquina: &Maquina,
    chave: &ChaveInstalacao,
) -> Requisicao {
    let corpo = json!({
        "nomeDesktop": maquina.nome,
        "sistemaOperacional": "Linux",
        "nomeUsuarioLocal": maquina.usuario_local,
        "dominioRede": maquina.dominio_rede,
        "chavePublica": chave.publica_pem(),
    });
    let caminho = format!("/api/manager/desktopid/usuario/{user_id}/organizacao/{organizacao_id}");
    post(
        url(&servidor.remoteid, &caminho),
        &corpo,
        Some(format!("Bearer {jwt}")),
    )
}

/// Se a conta tem celular pareado para aprovação. O caminho usa o código do
/// desktop, não o CPF.
pub fn status_celular(
    servidor: &Servidor,
    codigo_desktop: &str,
    agora: u64,
    chave: &ChaveInstalacao,
) -> Requisicao {
    let caminho = format!("/api/manager/desktopid/{codigo_desktop}/statusCelular");
    operacao(servidor, &caminho, momento(agora), chave)
}

pub fn carteira(
    servidor: &Servidor,
    codigo_desktop: &str,
    agora: u64,
    chave: &ChaveInstalacao,
) -> Requisicao {
    let caminho = format!("/api/manager/desktopid/{codigo_desktop}/carteira");
    operacao(servidor, &caminho, momento(agora), chave)
}

/// Abre a sessão de assinatura com PIN e OTP.
///
/// Os sete campos vão sempre, como no app oficial; `push` vai `false`. O PIN e
/// o OTP entram na canônica concatenados, por isso ela nunca vai para log.
pub fn tokensessao(
    servidor: &Servidor,
    codigo_desktop: &str,
    certificado: &Certificado,
    pin: &str,
    otp: &str,
    chave: &ChaveInstalacao,
) -> Requisicao {
    let corpo = json!({
        "desktopCode": codigo_desktop,
        "pin": pin,
        "otp": otp,
        "push": false,
        "nomeAplicacaoDesktop": NOME_APLICACAO,
        "issue": certificado.issue,
        "serialNumber": certificado.serial_number,
    });
    operacao(servidor, "/api/signature/tokensessao", corpo, chave)
}

/// Pede ao HSM a assinatura de `dados`.
///
/// O `id` do item é o índice, inteiro (a resposta o devolve como string). O
/// `algorithm` vai sempre, mesmo vazio: sem o campo o servidor responde
/// "Token inválido", com uma sessão boa, e o `Bearer` não muda, porque na
/// canônica string vazia e chave ausente são a mesma coisa.
pub fn request_hash(
    servidor: &Servidor,
    codigo_desktop: &str,
    session_token: &str,
    certificado: &Certificado,
    algoritmo: Algoritmo,
    dados: &[u8],
    chave: &ChaveInstalacao,
) -> Requisicao {
    let corpo = json!({
        "desktopCode": codigo_desktop,
        "sessionToken": session_token,
        "issue": certificado.issue,
        "serialNumber": certificado.serial_number,
        "algorithm": algoritmo.nome(),
        "hashArray": [{ "id": 0, "hash": b64(dados) }],
    });
    operacao(
        servidor,
        "/api/signature/requestHashSessionSignature",
        corpo,
        chave,
    )
}
