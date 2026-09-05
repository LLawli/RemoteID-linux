//! Interpretação da resposta do servidor: parte do protocolo, não do transporte.
//!
//! Duas armadilhas do backend moram aqui:
//!
//! 1. **HTTP 200 não é sucesso.** O backend responde 200 com
//!    `{"status": false, "message": "..."}` em erro de negócio. Quem confia no
//!    código HTTP conclui que deu certo. [`ok_json`] é o ponto único onde isso
//!    é checado.
//! 2. **O corpo de erro carrega a razão.** É nele que o backend explica o que
//!    faltou no payload; por isso o transporte o preserva mesmo em 4xx/5xx.

use serde_json::Value;

use remoteid_tipos::{Error, Result, ServerError};

use crate::config;

/// JSON da resposta, sem julgar o campo `status`.
pub fn json(status: u16, corpo: &str) -> Result<Value> {
    if corpo.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(corpo).map_err(|_| Error::RespostaNaoJson {
        status,
        trecho: corpo.chars().take(300).collect(),
    })
}

/// JSON da resposta, falhando quando o backend sinaliza erro de negócio.
///
/// Cobre as duas formas em que o `status` aparece: booleano `false` e a string
/// `"false"`.
pub fn ok_json(status: u16, corpo: &str) -> Result<Value> {
    let data = json(status, corpo)?;

    // O backend às vezes manda o booleano como string ("false").
    let negado = match data.get("status") {
        Some(Value::Bool(b)) => !b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("false"),
        _ => false, // login e registro não devolvem `status`
    };
    let http_ruim = !(200..300).contains(&status);
    if !negado && !http_ruim {
        return Ok(data);
    }

    let mensagem = ["message", "mensagem", "error", "exception"]
        .iter()
        .find_map(|k| data.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("HTTP {status}"));
    let (origem, hint) = config::classificar(&mensagem, corpo);
    Err(Error::Servidor(ServerError {
        http_status: status,
        message: mensagem,
        origem,
        hint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoteid_tipos::Origem;

    #[test]
    fn http_200_com_status_false_e_erro() {
        // A armadilha central do backend: 200 não quer dizer sucesso.
        let erro = ok_json(
            200,
            r#"{"status":false,"message":"Informe o Pin","token":null}"#,
        )
        .unwrap_err();
        match erro {
            Error::Servidor(s) => {
                assert_eq!(s.http_status, 200);
                assert_eq!(s.message, "Informe o Pin");
                assert_eq!(s.origem, Origem::Usuario);
                assert!(s.hint.is_some());
            }
            outro => panic!("classificou errado: {outro}"),
        }
    }

    #[test]
    fn request_hash_recusado_vem_com_certificate_e_id_array_nulos() {
        // A forma EXATA da recusa do requestHashSessionSignature, medida em
        // 05/09/2026 com `algorithm: "MD5"`: HTTP 200, `status: false`, e os
        // campos de sucesso presentes como null. É erro de domínio; o corpo
        // nulo não pode virar "requestHash sem idArray" (erro de estado).
        let erro = ok_json(
            200,
            r#"{"certificate":null,"idArray":null,"message":"Erro ao gerar assinatura RSA.","status":false}"#,
        )
        .unwrap_err();
        match erro {
            Error::Servidor(s) => {
                assert_eq!(s.http_status, 200);
                assert_eq!(s.message, "Erro ao gerar assinatura RSA.");
            }
            outro => panic!("classificou errado: {outro}"),
        }
    }

    #[test]
    fn http_200_com_status_true_passa() {
        let v = ok_json(200, r#"{"status":true,"message":"ok","token":"t"}"#).unwrap();
        assert_eq!(v["token"], "t");
    }

    #[test]
    fn resposta_sem_campo_status_passa() {
        // O login e o registro não devolvem `status`; só os dados.
        assert_eq!(
            ok_json(200, r#"{"token":"jwt","id":327989}"#).unwrap()["id"],
            327989
        );
    }

    #[test]
    fn erro_http_com_corpo_de_excecao_e_classificado() {
        let erro = ok_json(
            500,
            r#"{"exception":"UsuarioSenhaInvalidoException","message":"Usuário ou senha inválidos"}"#,
        )
        .unwrap_err();
        match erro {
            Error::Servidor(s) => assert_eq!(s.origem, Origem::Usuario),
            outro => panic!("esperava erro de servidor: {outro}"),
        }
    }

    #[test]
    fn corpo_que_nao_e_json_vira_erro_legivel() {
        assert!(matches!(
            ok_json(502, "<html>Bad Gateway</html>"),
            Err(Error::RespostaNaoJson { .. })
        ));
    }
}
