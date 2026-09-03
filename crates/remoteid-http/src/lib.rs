//! Transporte HTTP, com toda troca registrada no log de diagnóstico.
//!
//! Duas decisões que não são detalhe:
//!
//! 1. **O corpo de erro é preservado.** O `ureq` trata 4xx/5xx como erro de
//!    Rust por padrão e descarta o corpo; aqui isso é desligado
//!    (`http_status_as_error(false)`), porque é exatamente no corpo que o
//!    backend explica o que faltou no payload.
//! 2. **HTTP 200 não é sucesso.** O backend responde 200 com
//!    `{"status": false, "message": "..."}` em erro de negócio. Quem confia no
//!    código HTTP conclui que deu certo. [`Resposta::ok_json`] é o ponto único
//!    onde isso é checado.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use remoteid_protocolo_servidor::config;
use remoteid_portas::{Diagnostico, RequisicaoHttp, RespostaHttp, TransporteRemoteId};
use remoteid_tipos::{Error, Result, ServerError};

pub struct Resposta {
    pub status: u16,
    pub corpo: String,
}

impl Resposta {
    /// JSON da resposta, sem julgar o campo `status`.
    pub fn json(&self) -> Result<Value> {
        if self.corpo.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&self.corpo).map_err(|_| Error::RespostaNaoJson {
            status: self.status,
            trecho: self.corpo.chars().take(300).collect(),
        })
    }

    /// JSON da resposta, falhando quando o backend sinaliza erro de negócio.
    ///
    /// Cobre as duas formas em que o `status` aparece: booleano `false` e a
    /// string `"false"`.
    pub fn ok_json(&self) -> Result<Value> {
        let data = self.json()?;

        // O backend às vezes manda o booleano como string ("false").
        let negado = match data.get("status") {
            Some(Value::Bool(b)) => !b,
            Some(Value::String(s)) => s.eq_ignore_ascii_case("false"),
            _ => false, // login e registro não devolvem `status`
        };
        let http_ruim = !(200..300).contains(&self.status);
        if !negado && !http_ruim {
            return Ok(data);
        }

        let mensagem = ["message", "mensagem", "error", "exception"]
            .iter()
            .find_map(|k| data.get(*k).and_then(|v| v.as_str()))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {}", self.status));
        let (origem, hint) = config::classificar(&mensagem, &self.corpo);
        Err(Error::Servidor(ServerError {
            http_status: self.status,
            message: mensagem,
            origem,
            hint,
        }))
    }
}

pub struct Http {
    agente: ureq::Agent,
    diag: Arc<dyn Diagnostico>,
}

impl Http {
    pub fn novo(diag: Arc<dyn Diagnostico>, timeout: Duration) -> Http {
        let cfg = ureq::Agent::config_builder()
            // Sem isso o corpo de um 4xx/5xx some, e é nele que está a razão.
            .http_status_as_error(false)
            .user_agent(config::USER_AGENT)
            .timeout_global(Some(timeout))
            .build();
        Http { agente: ureq::Agent::new_with_config(cfg), diag }
    }

    /// Faz a requisição e registra os dois lados no diagnóstico.
    ///
    /// `rotulo` é o nome do passo do protocolo ("carteira", "tokensessao
    /// (pin+otp)"), e é por ele que se acha a troca no log depois.
    pub fn requisitar(
        &self,
        metodo: &str,
        url: &str,
        corpo: Option<&Value>,
        bearer: Option<&str>,
        rotulo: &str,
    ) -> Result<Resposta> {
        let corpo_txt = corpo.map(|c| c.to_string());

        self.diag.evento(
            "http.request",
            json!({
                "rotulo": rotulo,
                "metodo": metodo,
                "url": url,
                "authorization": bearer.map(|b| format!("Bearer {b}")),
                "body": corpo.cloned().unwrap_or(Value::Null),
            }),
        );

        // GET e POST são tipos diferentes no ureq 3 (typestate), então cada um
        // monta o seu builder; o que compartilham são os cabeçalhos.
        let autorizacao = bearer.map(|b| format!("Bearer {b}"));
        let resultado = match metodo {
            "GET" => {
                let mut req = self.agente.get(url).header("Accept", "application/json");
                if let Some(a) = &autorizacao {
                    req = req.header("Authorization", a);
                }
                req.call()
            }
            "POST" => {
                let mut req = self.agente.post(url).header("Accept", "application/json");
                if let Some(a) = &autorizacao {
                    req = req.header("Authorization", a);
                }
                match &corpo_txt {
                    Some(txt) => {
                        // O corpo vai como TEXTO já serializado: reserializar
                        // aqui mudaria os bytes que a assinatura do Bearer
                        // cobre, e a assinatura deixaria de bater.
                        req.header("Content-Type", "application/json").send(txt.as_str())
                    }
                    None => req.send_empty(),
                }
            }
            outro => return Err(Error::uso(format!("método HTTP não suportado: {outro}"))),
        };

        let mut resp = match resultado {
            Ok(r) => r,
            Err(e) => {
                self.diag.evento(
                    "http.erro",
                    json!({"rotulo": rotulo, "url": url, "erro": e.to_string()}),
                );
                return Err(Error::Rede(format!("{url}: {e}")));
            }
        };

        let status = resp.status().as_u16();
        let corpo = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Rede(format!("{url}: corpo ilegível: {e}")))?;

        // O corpo entra no log já parseado quando é JSON, para a redação
        // alcançar os campos de dentro (o `token` da resposta, por exemplo).
        let corpo_log = serde_json::from_str::<Value>(&corpo).unwrap_or(Value::String(corpo.clone()));
        self.diag.evento(
            "http.response",
            json!({"rotulo": rotulo, "status": status, "bytes": corpo.len(), "body": corpo_log}),
        );

        Ok(Resposta { status, corpo })
    }
}

/// A porta de transporte: recebe a requisição já montada (corpo serializado,
/// Bearer calculado) e devolve o par status+corpo cru. A interpretação
/// ("HTTP 200 pode ser erro") é do domínio, não do transporte.
impl TransporteRemoteId for Http {
    fn requisitar(&self, req: &RequisicaoHttp) -> Result<RespostaHttp> {
        let r = Http::requisitar(
            self,
            &req.metodo,
            &req.url,
            req.corpo.as_ref(),
            req.bearer.as_deref(),
            &req.rotulo,
        )?;
        Ok(RespostaHttp { status: r.status, corpo: r.corpo })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, corpo: &str) -> Resposta {
        Resposta { status, corpo: corpo.to_string() }
    }

    #[test]
    fn http_200_com_status_false_e_erro() {
        // A armadilha central do backend: 200 não quer dizer sucesso.
        let r = resp(200, r#"{"status":false,"message":"Informe o Pin","token":null}"#);
        let erro = r.ok_json().unwrap_err();
        match erro {
            Error::Servidor(s) => {
                assert_eq!(s.http_status, 200);
                assert_eq!(s.message, "Informe o Pin");
                assert_eq!(s.origem, remoteid_tipos::Origem::Usuario);
                assert!(s.hint.is_some());
            }
            outro => panic!("classificou errado: {outro}"),
        }
    }

    #[test]
    fn http_200_com_status_true_passa() {
        let r = resp(200, r#"{"status":true,"message":"Token gerado com sucesso","token":"t"}"#);
        let v = r.ok_json().unwrap();
        assert_eq!(v["token"], "t");
    }

    #[test]
    fn resposta_sem_campo_status_passa() {
        // O login e o registro não devolvem `status`; só os dados.
        let r = resp(200, r#"{"token":"jwt","id":327989}"#);
        assert_eq!(r.ok_json().unwrap()["id"], 327989);
    }

    #[test]
    fn erro_http_com_corpo_de_excecao_e_classificado() {
        let r = resp(
            500,
            r#"{"exception":"UsuarioSenhaInvalidoException","message":"Usuário ou senha inválidos"}"#,
        );
        match r.ok_json().unwrap_err() {
            Error::Servidor(s) => assert_eq!(s.origem, remoteid_tipos::Origem::Usuario),
            outro => panic!("esperava erro de servidor: {outro}"),
        }
    }

    #[test]
    fn corpo_que_nao_e_json_vira_erro_legivel() {
        let r = resp(502, "<html>Bad Gateway</html>");
        assert!(matches!(r.ok_json(), Err(Error::RespostaNaoJson { .. })));
    }
}
