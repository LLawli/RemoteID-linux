//! O fluxo da conta e da assinatura: junta o protocolo, o transporte, o
//! estado e a chave da instalação.
//!
//! O motor roda dentro do módulo PKCS#11, no serviço do Âncora, e na janela.
//! Os dois processos dividem o estado em disco; por isso quem usa o motor por
//! muito tempo chama [`Motor::recarregar`] antes de cada operação.

use std::io;

use serde_json::{Value, json};

use crate::caminhos::Caminhos;
use crate::cripto::ChaveInstalacao;
use crate::diagnostico::Diagnostico;
use crate::estado::{Estado, TTL_SESSAO_S};
use crate::protocolo::classificacao::{self, Origem};
use crate::protocolo::requisicao::{self, Maquina};
use crate::protocolo::resposta::{self, Erro as ErroProtocolo};
use crate::protocolo::{Algoritmo, Certificado, Requisicao, Servidor};
use crate::transporte::{Resposta, Transporte};

/// Quantas vezes a pessoa pode errar o PIN ou o OTP dentro de uma mesma
/// assinatura antes de o erro subir.
pub const MAX_TENTATIVAS: u32 = 3;

#[derive(Debug)]
pub enum Erro {
    /// O servidor não foi alcançado.
    Rede(String),
    Protocolo(ErroProtocolo),
    /// Falta um passo da preparação (entrar, registrar, carteira).
    NaoPreparado(&'static str),
    /// O estado ou a chave não puderam ser lidos ou gravados.
    Disco(io::Error),
    /// A pessoa fechou o pedido de PIN e OTP.
    Cancelado,
    /// O servidor não assina estes dados neste modo.
    BlocoInvalido,
}

impl From<ErroProtocolo> for Erro {
    fn from(e: ErroProtocolo) -> Erro {
        Erro::Protocolo(e)
    }
}

impl From<io::Error> for Erro {
    fn from(e: io::Error) -> Erro {
        Erro::Disco(e)
    }
}

pub struct Fatores {
    pub pin: String,
    pub otp: String,
}

/// Quem pede o PIN e o OTP à pessoa: o diálogo da janela, ou fatores fixos
/// num teste.
pub trait Autorizador {
    /// `recusa` é a mensagem do servidor quando a tentativa anterior foi
    /// recusada. `None` de volta é a pessoa desistindo.
    fn pedir(&self, certificado: &Certificado, recusa: Option<&str>) -> Option<Fatores>;
}

pub struct Motor {
    servidor: Servidor,
    caminhos: Caminhos,
    pub estado: Estado,
    chave: ChaveInstalacao,
    transporte: Box<dyn Transporte>,
    relogio: Box<dyn Fn() -> u64 + Send>,
    diagnostico: Diagnostico,
    /// O JWT do login. Só o registro o usa, e ele não vai para o disco.
    jwt: Option<String>,
}

fn agora_do_sistema() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Motor {
    /// Carrega o estado e a chave da instalação, gerando a chave na primeira
    /// vez.
    pub fn abrir(
        caminhos: Caminhos,
        servidor: Servidor,
        transporte: Box<dyn Transporte>,
    ) -> Result<Motor, Erro> {
        Ok(Motor {
            estado: Estado::carregar(&caminhos.estado())?,
            chave: ChaveInstalacao::carregar_ou_gerar(&caminhos.chave())?,
            servidor,
            caminhos,
            transporte,
            relogio: Box::new(agora_do_sistema),
            diagnostico: Diagnostico::inerte(),
            jwt: None,
        })
    }

    pub fn com_relogio(mut self, relogio: impl Fn() -> u64 + Send + 'static) -> Motor {
        self.relogio = Box::new(relogio);
        self
    }

    pub fn com_diagnostico(mut self, diagnostico: Diagnostico) -> Motor {
        self.diagnostico = diagnostico;
        self
    }

    /// Relê o estado do disco, que o outro processo pode ter mudado.
    pub fn recarregar(&mut self) -> Result<(), Erro> {
        self.estado = Estado::carregar(&self.caminhos.estado())?;
        Ok(())
    }

    fn salvar(&self) -> Result<(), Erro> {
        Ok(self.estado.salvar(&self.caminhos.estado())?)
    }

    /// O único caminho até a rede, e por isso o único que registra.
    fn enviar(&self, requisicao: &Requisicao) -> Result<Resposta, Erro> {
        let json = |texto: &str| {
            serde_json::from_str::<Value>(texto).unwrap_or_else(|_| Value::String(texto.into()))
        };
        self.diagnostico.evento(
            "requisicao",
            json!({
                "metodo": requisicao.metodo.nome(),
                "url": requisicao.url,
                "autorizacao": requisicao.autorizacao,
                "corpo": requisicao.corpo.as_deref().map(json),
            }),
        );
        match self.transporte.enviar(requisicao) {
            Ok(resposta) => {
                self.diagnostico.evento(
                    "resposta",
                    json!({
                        "http": resposta.http,
                        "bytes": resposta.corpo.len(),
                        "corpo": json(&resposta.corpo),
                    }),
                );
                Ok(resposta)
            }
            Err(e) => {
                self.diagnostico.evento("rede", json!({ "erro": e.0 }));
                Err(Erro::Rede(e.0))
            }
        }
    }

    fn codigo_desktop(&self) -> Result<String, Erro> {
        self.estado
            .codigo_desktop
            .clone()
            .ok_or(Erro::NaoPreparado("esta máquina não está registrada"))
    }

    fn certificado(&self) -> Result<Certificado, Erro> {
        self.estado
            .certificado()
            .cloned()
            .ok_or(Erro::NaoPreparado("a carteira está vazia"))
    }

    /// Se o servidor responde: a única rota que não depende de conta.
    pub fn conectar(&self) -> Result<(), Erro> {
        let r = self.enviar(&requisicao::hierarquias(&self.servidor))?;
        resposta::ler(r.http, &r.corpo)?;
        Ok(())
    }

    pub fn entrar(&mut self, email: &str, senha: &str) -> Result<(), Erro> {
        let r = self.enviar(&requisicao::login(&self.servidor, email, senha))?;
        let login = resposta::login(r.http, &r.corpo)?;
        self.jwt = Some(login.token);
        self.estado.user_id = login.id;
        self.estado.organizacao_id = login.organizacao_id;
        self.estado.nome = login.nome;
        self.estado.cpf = login.cpf;
        self.estado.email = Some(email.into());
        Ok(())
    }

    /// Registra esta máquina na conta, com a chave pública da instalação.
    pub fn registrar(&mut self, maquina: &Maquina) -> Result<(), Erro> {
        let jwt = self
            .jwt
            .as_deref()
            .ok_or(Erro::NaoPreparado("entre na conta antes de registrar"))?;
        let user_id = self
            .estado
            .user_id
            .ok_or(Erro::NaoPreparado("o login não trouxe o id da conta"))?;
        let requisicao = requisicao::registrar(
            &self.servidor,
            jwt,
            user_id,
            self.estado.organizacao_id.unwrap_or(0),
            maquina,
            &self.chave,
        );
        let r = self.enviar(&requisicao)?;
        self.estado.codigo_desktop = Some(resposta::registro(r.http, &r.corpo)?);
        self.estado.nome_desktop = Some(maquina.nome.into());
        self.salvar()
    }

    pub fn atualizar_celular(&mut self) -> Result<bool, Erro> {
        let requisicao = requisicao::status_celular(
            &self.servidor,
            &self.codigo_desktop()?,
            (self.relogio)(),
            &self.chave,
        );
        let r = self.enviar(&requisicao)?;
        let pareado = resposta::status_celular(r.http, &r.corpo)?;
        self.estado.celular_pareado = Some(pareado);
        self.salvar()?;
        Ok(pareado)
    }

    pub fn atualizar_carteira(&mut self) -> Result<(), Erro> {
        let requisicao = requisicao::carteira(
            &self.servidor,
            &self.codigo_desktop()?,
            (self.relogio)(),
            &self.chave,
        );
        let r = self.enviar(&requisicao)?;
        self.estado.certificados = resposta::carteira(r.http, &r.corpo)?;
        self.salvar()
    }

    /// Tudo o que a primeira vez exige: entrar, registrar esta máquina e
    /// baixar a carteira. O celular só informa, e uma falha nele não impede o
    /// resto.
    pub fn preparar(&mut self, email: &str, senha: &str, maquina: &Maquina) -> Result<(), Erro> {
        self.entrar(email, senha)?;
        self.registrar(maquina)?;
        let _ = self.atualizar_celular();
        self.atualizar_carteira()
    }

    /// Abre uma sessão de assinatura, pedindo o PIN e o OTP de novo a cada
    /// recusa que a pessoa pode corrigir, até [`MAX_TENTATIVAS`]. Rede e
    /// servidor sobem na hora: ali o servidor não julgou os fatores.
    fn abrir_sessao(
        &self,
        certificado: &Certificado,
        autorizador: &dyn Autorizador,
    ) -> Result<String, Erro> {
        let codigo = self.codigo_desktop()?;
        let mut recusa: Option<String> = None;
        for tentativa in 1..=MAX_TENTATIVAS {
            let fatores = autorizador
                .pedir(certificado, recusa.as_deref())
                .ok_or(Erro::Cancelado)?;
            let requisicao = requisicao::tokensessao(
                &self.servidor,
                &codigo,
                certificado,
                &fatores.pin,
                &fatores.otp,
                &self.chave,
            );
            let r = self.enviar(&requisicao)?;
            match resposta::tokensessao(r.http, &r.corpo) {
                Ok(token) => return Ok(token),
                Err(ErroProtocolo::Servidor {
                    mensagem,
                    regra: Some(regra),
                    ..
                }) if regra.origem == Origem::Usuario && tentativa < MAX_TENTATIVAS => {
                    recusa = Some(mensagem);
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!("a última tentativa sempre devolve")
    }

    fn assinar_com_sessao(
        &self,
        token: &str,
        certificado: &Certificado,
        algoritmo: Algoritmo,
        dados: &[u8],
    ) -> Result<Vec<u8>, Erro> {
        let requisicao = requisicao::request_hash(
            &self.servidor,
            &self.codigo_desktop()?,
            token,
            certificado,
            algoritmo,
            dados,
            &self.chave,
        );
        let r = self.enviar(&requisicao)?;
        Ok(resposta::request_hash(r.http, &r.corpo)?)
    }

    /// Assina `dados` com o certificado ativo. Tenta primeiro a sessão em
    /// cache, sem pedir nada à pessoa; se o servidor disser que ela não vale
    /// mais, pede PIN e OTP, abre outra e assina. Para quem chama, a única
    /// diferença entre os dois caminhos é o tempo.
    ///
    /// Os dados são conferidos antes de tudo: um bloco que o servidor recusaria
    /// não pode gastar a sessão nem o OTP de ninguém.
    pub fn assinar(
        &mut self,
        algoritmo: Algoritmo,
        dados: &[u8],
        autorizador: &dyn Autorizador,
    ) -> Result<Vec<u8>, Erro> {
        if !algoritmo.aceita(dados) {
            return Err(Erro::BlocoInvalido);
        }
        let certificado = self.certificado()?;
        let chave = certificado.chave();

        let em_cache = self
            .estado
            .sessao(&chave, (self.relogio)(), TTL_SESSAO_S)
            .map(|s| s.token.clone());
        if let Some(token) = em_cache {
            match self.assinar_com_sessao(&token, &certificado, algoritmo, dados) {
                Err(Erro::Protocolo(ErroProtocolo::Servidor { mensagem, .. }))
                    if classificacao::falha_de_sessao(&mensagem, "") =>
                {
                    self.estado.esquecer_sessao(&chave);
                    self.salvar()?;
                }
                resultado => return resultado,
            }
        }

        let token = self.abrir_sessao(&certificado, autorizador)?;
        let assinatura = self.assinar_com_sessao(&token, &certificado, algoritmo, dados)?;
        self.estado.guardar_sessao(chave, token, (self.relogio)());
        self.salvar()?;
        Ok(assinatura)
    }

    /// Faz a próxima assinatura pedir PIN e OTP.
    pub fn reautorizar_proxima(&mut self) -> Result<(), Erro> {
        let chave = self.certificado()?.chave();
        self.estado.esquecer_sessao(&chave);
        self.salvar()
    }

    pub fn escolher_certificado(&mut self, chave: &str) -> Result<(), Erro> {
        if !self.estado.certificados.iter().any(|c| c.chave() == chave) {
            return Err(Erro::NaoPreparado("o certificado não está na carteira"));
        }
        self.estado.certificado_ativo = Some(chave.into());
        self.salvar()
    }
}
