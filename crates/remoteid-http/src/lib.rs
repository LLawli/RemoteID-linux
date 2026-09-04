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

use remoteid_portas::{Diagnostico, RequisicaoHttp, RespostaHttp, TransporteRemoteId};
use remoteid_protocolo_servidor::{config, resposta};
use remoteid_tipos::{Error, Result};

pub struct Resposta {
    pub status: u16,
    pub corpo: String,
}

impl Resposta {
    /// JSON da resposta, sem julgar o campo `status`. A interpretação é do
    /// domínio do protocolo, não do transporte (ver [`remoteid_protocolo_servidor::resposta`]).
    pub fn json(&self) -> Result<Value> {
        resposta::json(self.status, &self.corpo)
    }

    /// JSON da resposta, falhando quando o backend sinaliza erro de negócio
    /// ("HTTP 200 pode ser erro"). Delega ao domínio.
    pub fn ok_json(&self) -> Result<Value> {
        resposta::ok_json(self.status, &self.corpo)
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
        Http {
            agente: ureq::Agent::new_with_config(cfg),
            diag,
        }
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
                        req.header("Content-Type", "application/json")
                            .send(txt.as_str())
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
        let corpo_log =
            serde_json::from_str::<Value>(&corpo).unwrap_or(Value::String(corpo.clone()));
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
        Ok(RespostaHttp {
            status: r.status,
            corpo: r.corpo,
        })
    }
}

// A interpretação da resposta (e seus testes) mora no domínio
// `remoteid_protocolo_servidor::resposta`. O transporte em si é exercitado
// pelos testes de integração que sobem um servidor HTTP local.
