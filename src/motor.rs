//! O fluxo da conta e da assinatura: junta o protocolo, o transporte, o
//! estado e a chave da instalação.
//!
//! O motor roda dentro do módulo PKCS#11, no serviço do Âncora, e na janela.
//! Os dois processos dividem o estado em disco; por isso quem usa o motor por
//! muito tempo chama [`Motor::recarregar`] antes de cada operação, e toda
//! escrita passa por [`Estado::alterar`], que aplica só a mudança sobre o que
//! está no disco.

use std::io;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cadeia::{self, Cadeia};
use crate::caminhos::Caminhos;
use crate::cofre::{Cofre, SemCofre};
use crate::cripto::{ChaveInstalacao, b64, de_b64};
use crate::diagnostico::Diagnostico;
use crate::estado::{Estado, TTL_SESSAO_S};
use crate::pin::{self, Abertura};
use crate::protocolo::classificacao::{self, Origem};
use crate::protocolo::requisicao::{self, Maquina};
use crate::protocolo::resposta::{self, Erro as ErroProtocolo};
use crate::protocolo::{Algoritmo, Certificado, Requisicao, Servidor};
use crate::transporte::{Resposta, Transporte};

/// Quantas vezes a pessoa pode errar o PIN ou o OTP dentro de uma mesma
/// assinatura antes de o erro subir.
pub const MAX_TENTATIVAS: u32 = 3;

/// Quantos pacotes do `caIssuers` baixar para um certificado. Na ICP-Brasil o
/// primeiro já traz a cadeia inteira; os seguintes existem para a AC que
/// publica só o próprio certificado, e o teto impede que um AIA mal
/// configurado vire um laço de downloads.
pub const MAX_PACOTES_CADEIA: usize = 4;

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
    /// O PIN local errou vezes demais: a senha cifrada foi apagada e a conta
    /// saiu deste computador.
    PinBloqueado,
    /// O servidor não assina estes dados neste modo.
    BlocoInvalido,
    /// O `.p7s` não pôde ser montado ([`crate::cades`]).
    Envelope(String),
}

/// O que a pessoa lê de cada falha, na janela e no terminal.
impl std::fmt::Display for Erro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Erro::Protocolo(ErroProtocolo::Servidor { mensagem, .. }) if !mensagem.is_empty() => {
                f.write_str(mensagem)
            }
            Erro::Rede(_) => f.write_str("Sem conexão com a Certisign"),
            Erro::Protocolo(_) => f.write_str("A Certisign respondeu algo inesperado"),
            Erro::Disco(_) => f.write_str("Não foi possível gravar os dados"),
            Erro::NaoPreparado(motivo) => {
                let mut letras = motivo.chars();
                if let Some(primeira) = letras.next() {
                    write!(f, "{}{}", primeira.to_uppercase(), letras.as_str())?;
                }
                Ok(())
            }
            Erro::Cancelado => f.write_str("Cancelado"),
            Erro::PinBloqueado => f.write_str("PIN bloqueado: entre na conta de novo"),
            Erro::BlocoInvalido => f.write_str("Dados que a Certisign não assina"),
            Erro::Envelope(e) => write!(f, "O .p7s não pôde ser montado: {e}"),
        }
    }
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

/// O que a pessoa informa para abrir uma sessão. Vive só na memória e no
/// pipe do diálogo.
///
/// O servidor chama de PIN o que é a senha da conta, a mesma do login; o
/// campo do protocolo continua `pin`. Aqui `pin` é o PIN local, que abre a
/// senha cifrada no disco ([`crate::pin`]). Cada campo vem só quando a
/// [`Credencial`] o pediu.
#[derive(Serialize, Deserialize)]
pub struct Fatores {
    #[serde(default)]
    pub senha: Option<String>,
    #[serde(default)]
    pub pin: Option<String>,
    pub otp: String,
}

/// O que o diálogo pergunta, além do OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credencial<'a> {
    /// A senha está guardada (no chaveiro ou na memória deste processo): só o
    /// OTP.
    Guardada,
    /// O PIN local, que abre a senha cifrada no disco.
    Pin,
    /// A senha da conta: não há uma guardada, ou o servidor recusou a
    /// tentativa e não diz se o errado foi ela ou o OTP. `atual` é a
    /// guardada, para a pessoa só confirmar.
    Senha { atual: Option<&'a str> },
}

impl Credencial<'_> {
    fn nome(&self) -> &'static str {
        match self {
            Credencial::Guardada => "guardada",
            Credencial::Pin => "pin",
            Credencial::Senha { .. } => "senha",
        }
    }
}

/// Quem pede os fatores à pessoa: o diálogo da janela, ou fatores fixos num
/// teste.
pub trait Autorizador {
    /// `recusa` é a mensagem da tentativa anterior (do servidor, ou do PIN
    /// local errado). `None` de volta é a pessoa desistindo.
    fn pedir(
        &self,
        certificado: &Certificado,
        recusa: Option<&str>,
        credencial: Credencial<'_>,
    ) -> Option<Fatores>;
}

/// A senha que este processo já conhece, e o PIN que a abriu, até ele
/// fechar. Só serve à conta de `email`.
struct Memoria {
    email: String,
    senha: Zeroizing<String>,
    pin: Option<Zeroizing<String>>,
}

pub struct Motor {
    servidor: Servidor,
    caminhos: Caminhos,
    pub estado: Estado,
    chave: ChaveInstalacao,
    transporte: Box<dyn Transporte>,
    relogio: Box<dyn Fn() -> u64 + Send>,
    diagnostico: Diagnostico,
    /// Onde fica a senha da conta entre uma sessão e outra.
    cofre: Box<dyn Cofre>,
    memoria: Option<Memoria>,
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
            cofre: Box::new(SemCofre),
            memoria: None,
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

    pub fn com_cofre(mut self, cofre: Box<dyn Cofre>) -> Motor {
        self.cofre = cofre;
        self
    }

    /// Guarda no chaveiro a senha que o servidor acabou de aceitar. Devolve
    /// se deu.
    fn guardar_senha(&self, email: &str, senha: &str) -> bool {
        let resultado = self.cofre.guardar(email, senha);
        let guardada = resultado.is_ok();
        self.diagnostico.evento(
            "cofre",
            json!({ "guardada": guardada, "erro": resultado.err() }),
        );
        guardada
    }

    /// Sem chaveiro, cifra a senha da conta com um PIN local
    /// ([`crate::pin::valido`]): o PIN passa a ser pedido na primeira
    /// assinatura de cada processo.
    pub fn proteger_com_pin(&mut self, senha: &str, pin: &str) -> Result<(), Erro> {
        let email = self
            .estado
            .email
            .clone()
            .ok_or(Erro::NaoPreparado("entre na conta antes de criar o PIN"))?;
        pin::cifrar(&self.caminhos.senha_cifrada(), &email, senha, pin)?;
        self.diagnostico
            .evento("cofre", json!({ "arquivo": "criado" }));
        Ok(())
    }

    /// Lembra a senha que o servidor aceitou até o processo fechar e, se ela
    /// mudou, guarda a nova: no chaveiro, ou no arquivo com o PIN que este
    /// processo conhece.
    fn lembrar_senha(&mut self, email: &str, senha: &Zeroizing<String>, anterior: Option<&str>) {
        let pin = self
            .memoria
            .take()
            .filter(|m| m.email == email)
            .and_then(|m| m.pin);
        if anterior != Some(senha.as_str())
            && !self.guardar_senha(email, senha)
            && let Some(pin) = &pin
        {
            let resultado = pin::cifrar(&self.caminhos.senha_cifrada(), email, senha, pin);
            self.diagnostico.evento(
                "cofre",
                json!({ "arquivo": "trocado", "erro": resultado.err().map(|e| e.to_string()) }),
            );
        }
        self.memoria = Some(Memoria {
            email: email.into(),
            senha: senha.clone(),
            pin,
        });
    }

    /// Relê o estado do disco, que o outro processo pode ter mudado.
    pub fn recarregar(&mut self) -> Result<(), Erro> {
        self.estado = Estado::carregar(&self.caminhos.estado())?;
        Ok(())
    }

    fn alterar(&mut self, mudanca: impl FnOnce(&mut Estado)) -> Result<(), Erro> {
        self.estado = Estado::alterar(&self.caminhos.estado(), mudanca)?;
        Ok(())
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
        let codigo = resposta::registro(r.http, &r.corpo)?;
        // O login só fica em memória até aqui: uma conta sem esta máquina
        // registrada não serve para nada no disco.
        let conta = self.estado.clone();
        self.alterar(|e| {
            e.user_id = conta.user_id;
            e.organizacao_id = conta.organizacao_id;
            e.nome = conta.nome;
            e.cpf = conta.cpf;
            e.email = conta.email;
            e.codigo_desktop = Some(codigo);
            e.nome_desktop = Some(maquina.nome.into());
        })
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
        self.alterar(|e| e.celular_pareado = Some(pareado))?;
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
        let mut certificados = resposta::carteira(r.http, &r.corpo)?;
        // A cadeia não é pré-requisito: sem ela, fica a que o mesmo
        // certificado já tinha, ou nenhuma.
        for certificado in &mut certificados {
            let anterior = self
                .estado
                .certificados
                .iter()
                .find(|a| a.chave() == certificado.chave() && a.base64 == certificado.base64);
            certificado.cadeia = self
                .cadeia_de(certificado)
                .or_else(|| anterior.map(|a| a.cadeia.clone()))
                .unwrap_or_default();
        }
        self.alterar(|e| e.certificados = certificados)
    }

    /// A cadeia de `certificado` em base64, ou `None` se não deu para montá-la.
    fn cadeia_de(&self, certificado: &Certificado) -> Option<Vec<String>> {
        let resultado = certificado
            .base64
            .as_deref()
            .and_then(de_b64)
            .ok_or_else(|| "a carteira não trouxe o DER do certificado".to_string())
            .and_then(|der| self.baixar_cadeia(&der));
        match resultado {
            Ok(cadeia) => {
                self.diagnostico.evento(
                    "cadeia",
                    json!({ "autoridades": cadeia.autoridades.len(), "completa": cadeia.completa }),
                );
                // Nenhuma autoridade de um final que não é autoassinado: o
                // pacote não trouxe o emissor, e isso não é uma cadeia.
                (cadeia.completa || !cadeia.autoridades.is_empty())
                    .then(|| cadeia.autoridades.iter().map(|der| b64(der)).collect())
            }
            Err(motivo) => {
                self.diagnostico.evento("cadeia", json!({ "erro": motivo }));
                None
            }
        }
    }

    /// Segue o `caIssuers` a partir do certificado até a raiz, até o próximo
    /// elo não dizer de onde vem, ou até [`MAX_PACOTES_CADEIA`]. Uma falha
    /// depois do primeiro pacote fica com o que já veio: as intermediárias já
    /// servem ao validador.
    fn baixar_cadeia(&self, final_der: &[u8]) -> Result<Cadeia, String> {
        let mut candidatos = Vec::new();
        let mut visitadas: Vec<String> = Vec::new();
        let mut cadeia = cadeia::montar(final_der, &candidatos)?;
        while !cadeia.completa && visitadas.len() < MAX_PACOTES_CADEIA {
            let url = match cadeia::url_ca_issuers(cadeia::proximo_a_seguir(final_der, &cadeia))? {
                Some(url) if !visitadas.contains(&url) => url,
                None if visitadas.is_empty() => {
                    return Err("o certificado não declara um caIssuers HTTP".into());
                }
                _ => break,
            };
            let destino = self.servidor.url_do_repositorio(&url);
            visitadas.push(url);
            self.diagnostico
                .evento("repositorio", json!({ "url": destino }));
            let pacote = self
                .transporte
                .baixar(&destino)
                .map_err(|e| e.0)
                .and_then(|bytes| cadeia::certificados_do_pacote(&bytes));
            match pacote {
                Ok(certificados) => candidatos.extend(certificados),
                Err(motivo) if cadeia.autoridades.is_empty() => return Err(motivo),
                Err(_) => break,
            }
            cadeia = cadeia::montar(final_der, &candidatos)?;
        }
        Ok(cadeia)
    }

    /// Tudo o que a primeira vez exige: entrar, registrar esta máquina e
    /// baixar a carteira. O celular só informa, e uma falha nele não impede o
    /// resto.
    /// Entra, registra esta máquina e baixa a carteira. Devolve se a senha
    /// ficou no chaveiro; sem ele, quem chamou oferece
    /// [`Motor::proteger_com_pin`].
    pub fn preparar(&mut self, email: &str, senha: &str, maquina: &Maquina) -> Result<bool, Erro> {
        self.entrar(email, senha)?;
        // Um arquivo de outra entrada não abre com a conta nova e só
        // gastaria tentativas de PIN.
        pin::apagar(&self.caminhos.senha_cifrada())?;
        self.memoria = None;
        let no_chaveiro = self.guardar_senha(email, senha);
        self.registrar(maquina)?;
        let _ = self.atualizar_celular();
        self.atualizar_carteira()?;
        Ok(no_chaveiro)
    }

    /// Abre uma sessão de assinatura, pedindo o PIN e o OTP de novo a cada
    /// recusa que a pessoa pode corrigir, até [`MAX_TENTATIVAS`]. Rede e
    /// servidor sobem na hora: ali o servidor não julgou os fatores.
    fn abrir_sessao(
        &mut self,
        certificado: &Certificado,
        autorizador: &dyn Autorizador,
    ) -> Result<String, Erro> {
        let codigo = self.codigo_desktop()?;
        let email = self
            .estado
            .email
            .clone()
            .ok_or(Erro::NaoPreparado("a conta não tem e-mail"))?;
        let arquivo = self.caminhos.senha_cifrada();
        let da_memoria = self
            .memoria
            .as_ref()
            .filter(|m| m.email == email)
            .map(|m| m.senha.clone());
        let mut conhecida = da_memoria
            .clone()
            .or_else(|| self.cofre.ler(&email).map(Zeroizing::new));
        self.diagnostico.evento(
            "cofre",
            json!({
                "memoria": da_memoria.is_some(),
                "lida": da_memoria.is_none() && conhecida.is_some(),
                "arquivo": arquivo.exists(),
            }),
        );
        let mut recusa: Option<String> = None;
        let mut servidor_recusou = false;
        let mut tentativa = 0;
        loop {
            let credencial = match &conhecida {
                Some(s) if servidor_recusou => Credencial::Senha {
                    atual: Some(s.as_str()),
                },
                Some(_) => Credencial::Guardada,
                None if arquivo.exists() => Credencial::Pin,
                None => Credencial::Senha { atual: None },
            };
            self.diagnostico.evento(
                "pedido",
                json!({
                    "tentativa": tentativa + 1,
                    "recusa": recusa,
                    "credencial": credencial.nome(),
                }),
            );
            let cancelar = |m: &Motor| {
                m.diagnostico.evento("cancelado", json!({}));
                Err(Erro::Cancelado)
            };
            let Some(fatores) = autorizador.pedir(certificado, recusa.as_deref(), credencial)
            else {
                return cancelar(self);
            };
            let senha = match credencial {
                Credencial::Guardada => conhecida.clone().expect("guardada só com senha conhecida"),
                Credencial::Senha { .. } => match fatores.senha {
                    Some(s) => Zeroizing::new(s),
                    None => return cancelar(self),
                },
                Credencial::Pin => {
                    let Some(pin) = fatores.pin.map(Zeroizing::new) else {
                        return cancelar(self);
                    };
                    match pin::abrir(&arquivo, &email, &pin)? {
                        Abertura::Senha(s) => {
                            self.diagnostico
                                .evento("cofre", json!({ "arquivo": "aberto" }));
                            self.memoria = Some(Memoria {
                                email: email.clone(),
                                senha: s.clone(),
                                pin: Some(pin),
                            });
                            conhecida = Some(s.clone());
                            s
                        }
                        Abertura::Errado { restantes } => {
                            self.diagnostico.evento(
                                "cofre",
                                json!({ "arquivo": "pin errado", "restantes": restantes }),
                            );
                            recusa = Some(format!(
                                "PIN incorreto: mais {restantes} erro{} e a conta sai deste computador",
                                if restantes == 1 { "" } else { "s" }
                            ));
                            continue;
                        }
                        Abertura::Bloqueado => {
                            self.diagnostico
                                .evento("cofre", json!({ "arquivo": "bloqueado" }));
                            self.sair()?;
                            return Err(Erro::PinBloqueado);
                        }
                    }
                }
            };
            tentativa += 1;
            let requisicao = requisicao::tokensessao(
                &self.servidor,
                &codigo,
                certificado,
                &senha,
                &fatores.otp,
                &self.chave,
            );
            let r = self.enviar(&requisicao)?;
            match resposta::tokensessao(r.http, &r.corpo) {
                Ok(token) => {
                    let anterior = conhecida.as_ref().map(|s| s.to_string());
                    self.lembrar_senha(&email, &senha, anterior.as_deref());
                    return Ok(token);
                }
                Err(ErroProtocolo::Servidor {
                    mensagem,
                    regra: Some(regra),
                    ..
                }) if regra.origem == Origem::Usuario && tentativa < MAX_TENTATIVAS => {
                    recusa = Some(mensagem);
                    servidor_recusou = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
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

    /// Assina `dados` com o certificado ativo. Ver [`Motor::assinar_com`].
    pub fn assinar(
        &mut self,
        algoritmo: Algoritmo,
        dados: &[u8],
        autorizador: &dyn Autorizador,
    ) -> Result<Vec<u8>, Erro> {
        let certificado = self.certificado()?;
        self.assinar_com(&certificado, algoritmo, dados, autorizador)
    }

    /// Assina `dados` com `certificado`. Tenta primeiro a sessão em cache, sem
    /// pedir nada à pessoa; se o servidor disser que ela não vale mais, pede
    /// PIN e OTP, abre outra e assina. Para quem chama, a única diferença entre
    /// os dois caminhos é o tempo.
    ///
    /// O módulo PKCS#11 passa o certificado que o token mostra, e não o ativo:
    /// se a janela trocar a escolha com o aplicativo aberto, a assinatura ainda
    /// tem de conferir com o certificado que ele leu.
    ///
    /// Os dados são conferidos antes de tudo: um bloco que o servidor recusaria
    /// não pode gastar a sessão nem o OTP de ninguém.
    pub fn assinar_com(
        &mut self,
        certificado: &Certificado,
        algoritmo: Algoritmo,
        dados: &[u8],
        autorizador: &dyn Autorizador,
    ) -> Result<Vec<u8>, Erro> {
        if !algoritmo.aceita(dados) {
            return Err(Erro::BlocoInvalido);
        }
        let chave = certificado.chave();

        let em_cache = self
            .estado
            .sessao(&chave, (self.relogio)(), TTL_SESSAO_S)
            .map(|s| s.token.clone());
        if let Some(token) = em_cache {
            match self.assinar_com_sessao(&token, certificado, algoritmo, dados) {
                Err(Erro::Protocolo(ErroProtocolo::Servidor { mensagem, .. }))
                    if classificacao::falha_de_sessao(&mensagem, "") =>
                {
                    self.alterar(|e| e.esquecer_sessao(&chave))?;
                }
                resultado => return resultado,
            }
        }

        let token = self.abrir_sessao(certificado, autorizador)?;
        let assinatura = self.assinar_com_sessao(&token, certificado, algoritmo, dados)?;
        let agora = (self.relogio)();
        self.alterar(|e| e.guardar_sessao(chave, token, agora))?;
        Ok(assinatura)
    }

    /// Faz a próxima assinatura pedir PIN e OTP.
    pub fn reautorizar_proxima(&mut self) -> Result<(), Erro> {
        let chave = self.certificado()?.chave();
        self.alterar(|e| e.esquecer_sessao(&chave))
    }

    /// Sai da conta: esquece o registro desta máquina, a carteira, as sessões
    /// e a senha guardada. A chave da instalação fica, e o próximo registro a
    /// usa.
    pub fn sair(&mut self) -> Result<(), Erro> {
        self.jwt = None;
        self.memoria = None;
        pin::apagar(&self.caminhos.senha_cifrada())?;
        if let Some(email) = &self.estado.email {
            let resultado = self.cofre.apagar(email);
            self.diagnostico.evento(
                "cofre",
                json!({ "apagada": resultado.is_ok(), "erro": resultado.err() }),
            );
        }
        self.alterar(|e| *e = Estado::default())
    }

    pub fn escolher_certificado(&mut self, chave: &str) -> Result<(), Erro> {
        if !self.estado.certificados.iter().any(|c| c.chave() == chave) {
            return Err(Erro::NaoPreparado("o certificado não está na carteira"));
        }
        self.alterar(|e| e.certificado_ativo = Some(chave.into()))
    }
}
