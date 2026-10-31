//! A leitura das respostas.
//!
//! **HTTP 200 não é sucesso.** O servidor responde 200 com
//! `{"status": false, "message": "..."}` em erro de negócio, e às vezes manda o
//! `status` como a string `"false"`. Toda leitura passa por [`ler`], o único
//! lugar que decide se a resposta deu certo.

use serde_json::Value;

use super::Certificado;
use super::classificacao::{self, Regra};
use crate::cripto::de_b64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erro {
    /// O servidor recusou, e disse por quê.
    Servidor {
        http: u16,
        mensagem: String,
        regra: Option<&'static Regra>,
    },
    /// A resposta nem era JSON (página de erro de um gateway, por exemplo).
    NaoJson { http: u16, trecho: String },
    /// Era JSON de sucesso, mas sem o que deveria trazer.
    Malformada(&'static str),
    /// O pedido passou, e o HSM recusou assinar aquele hash.
    HsmRecusou(String),
}

/// Quantos caracteres de uma resposta que não é JSON vão para o erro.
const TRECHO: usize = 300;

/// O JSON da resposta, ou o erro que ela carrega.
pub fn ler(http: u16, corpo: &str) -> Result<Value, Erro> {
    let dados = if corpo.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(corpo).map_err(|_| Erro::NaoJson {
            http,
            trecho: corpo.chars().take(TRECHO).collect(),
        })?
    };
    let negado = match dados.get("status") {
        Some(Value::Bool(b)) => !b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("false"),
        // O login e o registro não devolvem `status`.
        _ => false,
    };
    if !negado && (200..300).contains(&http) {
        return Ok(dados);
    }
    // A primeira chave que é texto vale, mesmo vazia: vazia, cai no código.
    let mensagem = ["message", "mensagem", "error", "exception"]
        .iter()
        .find_map(|k| dados.get(*k).and_then(Value::as_str))
        .filter(|m| !m.is_empty())
        .map_or_else(|| format!("HTTP {http}"), str::to_string);
    let regra = classificacao::classificar(&mensagem, corpo);
    Err(Erro::Servidor {
        http,
        mensagem,
        regra,
    })
}

fn texto(dados: &Value, chave: &str) -> Option<String> {
    dados.get(chave).and_then(Value::as_str).map(str::to_string)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// O JWT, que só o registro usa. Não persiste.
    pub token: String,
    pub id: Option<i64>,
    pub organizacao_id: Option<i64>,
    pub nome: Option<String>,
    pub cpf: Option<String>,
}

pub fn login(http: u16, corpo: &str) -> Result<Login, Erro> {
    let dados = ler(http, corpo)?;
    Ok(Login {
        token: texto(&dados, "token").ok_or(Erro::Malformada("login sem token"))?,
        id: dados.get("id").and_then(Value::as_i64),
        organizacao_id: dados.get("organizacaoId").and_then(Value::as_i64),
        nome: texto(&dados, "nome"),
        cpf: texto(&dados, "cpf"),
    })
}

/// O `codigoDesktop` desta máquina.
pub fn registro(http: u16, corpo: &str) -> Result<String, Erro> {
    texto(&ler(http, corpo)?, "codigoDesktop").ok_or(Erro::Malformada("registro sem codigoDesktop"))
}

/// Se a conta tem celular pareado. Ausente vale `false`.
pub fn status_celular(http: u16, corpo: &str) -> Result<bool, Erro> {
    Ok(ler(http, corpo)?
        .get("usuarioPossuiCodigoPush")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

/// Os certificados da carteira. Item sem `keyName` é pulado; `keyName` sem
/// `;` invalida a carteira inteira, porque aí o formato mudou.
pub fn carteira(http: u16, corpo: &str) -> Result<Vec<Certificado>, Erro> {
    let dados = ler(http, corpo)?;
    let lista = dados
        .get("certificados")
        .and_then(Value::as_array)
        .ok_or(Erro::Malformada("carteira sem a lista de certificados"))?;
    let mut certificados = Vec::new();
    for item in lista {
        let Some(key_name) = item.get("keyName").and_then(Value::as_str) else {
            continue;
        };
        let certificado = Certificado::do_key_name(key_name, texto(item, "base64"))
            .ok_or(Erro::Malformada("keyName sem ';'"))?;
        certificados.push(certificado);
    }
    if certificados.is_empty() {
        return Err(Erro::Malformada("carteira sem certificado utilizável"));
    }
    Ok(certificados)
}

/// O `sessionToken`. É opaco: um registro com campos separados por `;` que só
/// se repassa inteiro no `requestHash`.
pub fn tokensessao(http: u16, corpo: &str) -> Result<String, Erro> {
    texto(&ler(http, corpo)?, "token")
        .filter(|t| !t.is_empty())
        .ok_or(Erro::Malformada("tokensessao sem token"))
}

/// A assinatura crua (256 bytes para RSA-2048), do primeiro item do
/// `idArray`. Cada item tem o próprio `status`: o pedido pode passar e a
/// assinatura daquele hash falhar.
pub fn request_hash(http: u16, corpo: &str) -> Result<Vec<u8>, Erro> {
    let dados = ler(http, corpo)?;
    let item = dados
        .get("idArray")
        .and_then(Value::as_array)
        .and_then(|itens| itens.first())
        .ok_or(Erro::Malformada("requestHash sem idArray"))?;
    if item.get("status").and_then(Value::as_bool) == Some(false) {
        let mensagem = texto(item, "message").unwrap_or_else(|| "sem detalhe".into());
        return Err(Erro::HsmRecusou(mensagem));
    }
    let assinatura = texto(item, "signatureBase64")
        .ok_or(Erro::Malformada("requestHash sem signatureBase64"))?;
    de_b64(&assinatura).ok_or(Erro::Malformada("signatureBase64 não é base64"))
}
