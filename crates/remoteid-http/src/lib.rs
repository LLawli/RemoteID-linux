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

use remoteid_portas::{
    Diagnostico, FonteDeCadeia, RequisicaoHttp, RespostaHttp, TransporteRemoteId,
};
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

/// Teto do pacote do `caIssuers`. Um `.p7c` da ICP-Brasil com a cadeia
/// inteira tem uns 5 KB; o teto só existe para um servidor errado (ou uma
/// página de erro gigante) não encher a memória do daemon.
const TETO_PACOTE_BYTES: u64 = 1024 * 1024;

/// O download do `caIssuers`: a porta [`FonteDeCadeia`] sobre HTTP.
///
/// Agente próprio, e não o do [`Http`], porque nada do protocolo do RemoteID
/// vale aqui: o servidor é o repositório público da AC, a resposta é binária, e
/// o `User-Agent` do app oficial não tem por que ir junto.
pub struct BaixadorAia {
    agente: ureq::Agent,
    diag: Arc<dyn Diagnostico>,
    /// Em modo de teste, a origem (`http://host:porta`) que substitui a da URL
    /// do certificado. Ver [`BaixadorAia::redirecionar_para`].
    origem_teste: Option<String>,
}

impl BaixadorAia {
    pub fn novo(diag: Arc<dyn Diagnostico>, timeout: Duration) -> BaixadorAia {
        let cfg = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        BaixadorAia {
            agente: ureq::Agent::new_with_config(cfg),
            diag,
            origem_teste: None,
        }
    }

    /// Troca a origem de toda URL baixada por `origem`, mantendo o caminho.
    ///
    /// Só para o modo de teste: o certificado sintético do mock declara o AIA
    /// em `http://localhost:8799`, mas o gate de integração sobe o mock numa
    /// porta efêmera. Sem isto, a cadeia só funcionaria na porta padrão.
    pub fn redirecionar_para(mut self, origem: &str) -> BaixadorAia {
        self.origem_teste = Some(origem.trim_end_matches('/').to_string());
        self
    }
}

/// `url` com a origem (esquema, host e porta) trocada por `origem`.
fn com_origem(url: &str, origem: &str) -> String {
    let resto = url.split_once("://").map_or(url, |(_, r)| r);
    let caminho = resto.find('/').map_or("/", |i| &resto[i..]);
    format!("{origem}{caminho}")
}

impl FonteDeCadeia for BaixadorAia {
    fn baixar(&self, url: &str) -> Result<Vec<u8>> {
        let url = match &self.origem_teste {
            Some(origem) => com_origem(url, origem),
            None => url.to_string(),
        };
        let url = url.as_str();
        self.diag.evento("aia.request", json!({ "url": url }));

        let mut resp = match self.agente.get(url).call() {
            Ok(r) => r,
            Err(e) => {
                self.diag
                    .evento("aia.erro", json!({"url": url, "erro": e.to_string()}));
                return Err(Error::Rede(format!("{url}: {e}")));
            }
        };
        let status = resp.status().as_u16();
        if status != 200 {
            self.diag
                .evento("aia.response", json!({"url": url, "status": status}));
            return Err(Error::Rede(format!("{url}: HTTP {status}")));
        }
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(TETO_PACOTE_BYTES)
            .read_to_vec()
            .map_err(|e| Error::Rede(format!("{url}: corpo ilegível: {e}")))?;
        self.diag.evento(
            "aia.response",
            json!({"url": url, "status": status, "bytes": bytes.len()}),
        );
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_origem_de_teste_troca_host_e_porta_e_mantem_o_caminho() {
        assert_eq!(
            com_origem(
                "http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c",
                "http://localhost:41234"
            ),
            "http://localhost:41234/repositorio/AC_TESTE_DESKTOPID.p7c"
        );
        assert_eq!(
            com_origem("http://icp-brasil.certisign.com.br", "http://x:1"),
            "http://x:1/"
        );
    }
}

// A interpretação da resposta (e seus testes) mora no domínio
// `remoteid_protocolo_servidor::resposta`. O transporte em si é exercitado
// pelos testes de integração que sobem um servidor HTTP local.
