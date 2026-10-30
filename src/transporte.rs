//! Leva a [`Requisicao`] ao servidor e traz a resposta, sem julgá-la: quem
//! decide se deu certo é [`crate::protocolo::resposta`], porque HTTP 200 pode
//! ser erro e um 4xx traz no corpo o motivo.

use std::time::Duration;

use crate::protocolo::{Metodo, Requisicao, USER_AGENT};

/// Quanto uma requisição pode levar, do começo ao fim.
pub const TEMPO_LIMITE: Duration = Duration::from_secs(30);

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
}

pub struct Http(ureq::Agent);

impl Http {
    pub fn novo(tempo_limite: Duration) -> Http {
        let configuracao = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(USER_AGENT)
            .timeout_global(Some(tempo_limite))
            .build();
        Http(ureq::Agent::new_with_config(configuracao))
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
                let mut pedido = self.0.get(&requisicao.url);
                for (nome, valor) in cabecalhos {
                    pedido = pedido.header(nome, valor);
                }
                pedido.call()
            }
            (Metodo::Post, corpo) => {
                let mut pedido = self.0.post(&requisicao.url);
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
}
