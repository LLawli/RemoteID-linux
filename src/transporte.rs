//! Leva a [`Requisicao`] ao servidor e traz a resposta, sem julgá-la: quem
//! decide se deu certo é [`crate::protocolo::resposta`], porque HTTP 200 pode
//! ser erro e um 4xx traz no corpo o motivo.

use std::time::Duration;

use crate::protocolo::{Metodo, Requisicao, USER_AGENT};

/// Quanto uma requisição pode levar, do começo ao fim.
pub const TEMPO_LIMITE: Duration = Duration::from_secs(30);

/// Quanto o download de um pacote do `caIssuers` pode levar. Menor que o da
/// Certisign: a cadeia é um extra da carteira, e uma AC que não responde não
/// pode segurar quem entra na conta.
pub const TEMPO_LIMITE_REPOSITORIO: Duration = Duration::from_secs(15);

/// O maior pacote do `caIssuers` aceito. Um `.p7c` da ICP-Brasil tem poucos
/// KB.
pub const TETO_PACOTE: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resposta {
    pub http: u16,
    pub corpo: String,
}

/// A requisição não chegou ao servidor, ou a resposta não voltou.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErroRede(pub String);

pub trait Transporte: Send {
    fn enviar(&self, requisicao: &Requisicao) -> Result<Resposta, ErroRede>;

    /// Um GET simples ao repositório de uma AC, fora do protocolo da
    /// Certisign: sem `Bearer` e sem o User-Agent do app oficial.
    fn baixar(&self, url: &str) -> Result<Vec<u8>, ErroRede>;
}

pub struct Http {
    certisign: ureq::Agent,
    repositorio: ureq::Agent,
}

impl Http {
    pub fn novo(tempo_limite: Duration) -> Http {
        let certisign = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(USER_AGENT)
            .timeout_global(Some(tempo_limite))
            .build();
        let repositorio = ureq::Agent::config_builder()
            .timeout_global(Some(tempo_limite.min(TEMPO_LIMITE_REPOSITORIO)))
            .build();
        Http {
            certisign: ureq::Agent::new_with_config(certisign),
            repositorio: ureq::Agent::new_with_config(repositorio),
        }
    }
}

impl Transporte for Http {
    fn enviar(&self, requisicao: &Requisicao) -> Result<Resposta, ErroRede> {
        let erro = |e: ureq::Error| ErroRede(format!("{}: {e}", requisicao.url));
        // O User-Agent vai pela configuração do agente; repetido aqui, sairia
        // duas vezes.
        let cabecalhos = requisicao
            .cabecalhos()
            .into_iter()
            .filter(|(nome, _)| *nome != "user-agent");
        let resposta = match (requisicao.metodo, &requisicao.corpo) {
            (Metodo::Get, _) => {
                let mut pedido = self.certisign.get(&requisicao.url);
                for (nome, valor) in cabecalhos {
                    pedido = pedido.header(nome, valor);
                }
                pedido.call()
            }
            (Metodo::Post, corpo) => {
                let mut pedido = self.certisign.post(&requisicao.url);
                for (nome, valor) in cabecalhos {
                    pedido = pedido.header(nome, valor);
                }
                match corpo {
                    Some(corpo) => pedido.send(corpo.as_str()),
                    None => pedido.send_empty(),
                }
            }
        };
        let mut resposta = resposta.map_err(erro)?;
        let http = resposta.status().as_u16();
        let corpo = resposta.body_mut().read_to_string().map_err(erro)?;
        Ok(Resposta { http, corpo })
    }

    fn baixar(&self, url: &str) -> Result<Vec<u8>, ErroRede> {
        let erro = |e: ureq::Error| ErroRede(format!("{url}: {e}"));
        self.repositorio
            .get(url)
            .call()
            .map_err(erro)?
            .body_mut()
            .with_config()
            .limit(TETO_PACOTE)
            .read_to_vec()
            .map_err(erro)
    }
}
