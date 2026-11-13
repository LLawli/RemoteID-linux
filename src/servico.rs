//! O RemoteID para outros programas: tudo o que a janela faz, num protocolo de
//! JSON por linha, sem GTK. O `remoteid servir` o fala pelo stdin e stdout, ou
//! num socket Unix; quem chama pode ser um gateway HTTP, um webapp ou o
//! backend de um app de celular, que pede o código do autenticador à pessoa
//! do jeito dele.
//!
//! Cada linha que chega é um pedido com `id` e `op`; cada pedido recebe uma
//! linha de volta, com o mesmo `id` e `ok` ou `erro`. No meio de um `assinar`,
//! quando a sessão em cache não vale mais, o serviço manda
//! `{"id":…,"pedir":{…}}` e espera `{"id":…,"fatores":{"otp":…}}` (com `senha`
//! ou `pin`, se pedidos) ou `{"id":…,"cancelar":true}`. O protocolo inteiro
//! está em `docs/servico.md`.
//!
//! A senha guardada nunca sai pelo canal: depois de uma recusa do servidor, o
//! pedido diz só `senha_guardada`, e quem chama omite a `senha` para mantê-la.
//! Nada do que entra (senha, PIN, OTP, documento) vai para o diagnóstico.

use std::cell::RefCell;
use std::io::{BufRead, Write};

use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cades;
use crate::carteira::{self, Sessao};
use crate::cripto::{b64, de_b64, de_hex, sha256};
use crate::estado::Estado;
use crate::motor::{Autorizador, Credencial, Erro, Fatores, Motor};
use crate::pin;
use crate::protocolo::requisicao::Maquina;
use crate::protocolo::{Algoritmo, Certificado};
use crate::x509;

/// O que cada `op` recebe.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operacao {
    /// A conta, esta máquina e a carteira, sem ir à rede.
    Estado,
    /// Baixa de novo a carteira e o estado do celular.
    Atualizar,
    /// Entra na conta, registra esta máquina e baixa a carteira. Sem
    /// chaveiro, `pin` cifra a senha no disco ([`crate::pin`]).
    Entrar {
        email: String,
        senha: String,
        #[serde(default)]
        pin: Option<String>,
    },
    /// Escolhe o certificado que assina, pela chave ou pelo número de série.
    Usar {
        certificado: String,
    },
    /// Faz a próxima assinatura pedir os fatores.
    Reautorizar,
    Sair,
    Assinar {
        #[serde(default)]
        formato: Formato,
        /// O SHA-256 do documento, em hexadecimal.
        #[serde(default)]
        hash: Option<String>,
        /// O documento em base64, no lugar do `hash`.
        #[serde(default)]
        documento: Option<String>,
        /// Só no `cru`: o DigestInfo pronto, em base64, no lugar do `hash`,
        /// para assinar o resumo de qualquer algoritmo (o TLS 1.2 pede
        /// SHA-384 e SHA-512, por exemplo).
        #[serde(default)]
        digest_info: Option<String>,
        /// A chave ou a série; sem ele, o certificado ativo.
        #[serde(default)]
        certificado: Option<String>,
    },
}

#[derive(Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Formato {
    /// `.p7s` destacado, na política AD-RB.
    #[default]
    Destacado,
    /// `.p7s` com o documento dentro.
    Anexado,
    /// A assinatura RSA (PKCS#1 v1.5) do hash SHA-256 ou do DigestInfo, sem
    /// envelope.
    Cru,
}

#[derive(Deserialize)]
struct Linha {
    #[serde(default)]
    id: Value,
    #[serde(flatten)]
    resto: Value,
}

/// A resposta de quem chama a um `pedir`.
#[derive(Deserialize)]
struct Resposta {
    #[serde(default)]
    fatores: Option<Fatores>,
    #[serde(default)]
    cancelar: bool,
}

/// Uma falha do pedido em si, antes de chegar ao motor.
const PEDIDO_INVALIDO: &str = "pedido_invalido";

fn erro(id: &Value, tipo: &str, mensagem: &str) -> Value {
    json!({ "id": id, "erro": { "tipo": tipo, "mensagem": mensagem } })
}

/// Os dois lados da conversa. O motor pergunta no meio de uma operação, então
/// quem lê e quem escreve ficam emprestados por dentro.
struct Canal<R, W> {
    leitura: RefCell<R>,
    escrita: RefCell<W>,
}

impl<R: BufRead, W: Write> Canal<R, W> {
    /// A próxima linha não vazia, ou `None` no fim. Apagada da memória ao
    /// sair de cena: pode levar a senha ou o OTP.
    fn ler(&self) -> Option<Zeroizing<String>> {
        loop {
            let mut linha = Zeroizing::new(String::new());
            match self.leitura.borrow_mut().read_line(&mut linha) {
                Ok(0) | Err(_) => return None,
                Ok(_) if linha.trim().is_empty() => continue,
                Ok(_) => return Some(linha),
            }
        }
    }

    /// Escreve uma linha. Devolve se deu: um par que fechou encerra a conversa.
    fn escrever(&self, valor: &Value) -> bool {
        let mut escrita = self.escrita.borrow_mut();
        writeln!(escrita, "{valor}")
            .and_then(|()| escrita.flush())
            .is_ok()
    }
}

/// Pergunta os fatores pelo canal, no `id` do `assinar` em curso.
struct PeloCanal<'a, R, W> {
    id: &'a Value,
    canal: &'a Canal<R, W>,
}

impl<R: BufRead, W: Write> Autorizador for PeloCanal<'_, R, W> {
    fn pedir(
        &self,
        certificado: &Certificado,
        recusa: Option<&str>,
        credencial: Credencial<'_>,
    ) -> Option<Fatores> {
        let titular = certificado
            .base64
            .as_deref()
            .and_then(de_b64)
            .and_then(|der| x509::ler(&der).ok()?.nome);
        let atual = match credencial {
            Credencial::Senha { atual } => atual,
            _ => None,
        };
        let pedido = json!({
            "id": self.id,
            "pedir": {
                "titular": titular,
                "recusa": recusa,
                "pedir_senha": matches!(credencial, Credencial::Senha { .. }),
                "pedir_pin": credencial == Credencial::Pin,
                "senha_guardada": atual.is_some(),
            },
        });
        if !self.canal.escrever(&pedido) {
            return None;
        }
        loop {
            let linha = self.canal.ler()?;
            let Ok(Linha { id, resto }) = serde_json::from_str::<Linha>(&linha) else {
                self.canal
                    .escrever(&erro(&Value::Null, PEDIDO_INVALIDO, "JSON inválido"));
                continue;
            };
            if &id != self.id {
                self.canal.escrever(&erro(
                    &id,
                    "ocupado",
                    "uma assinatura espera os fatores neste canal",
                ));
                continue;
            }
            let Ok(resposta) = serde_json::from_value::<Resposta>(resto) else {
                self.canal
                    .escrever(&erro(&id, PEDIDO_INVALIDO, "esperava fatores ou cancelar"));
                continue;
            };
            if resposta.cancelar {
                return None;
            }
            let Some(mut fatores) = resposta.fatores else {
                self.canal
                    .escrever(&erro(&id, PEDIDO_INVALIDO, "esperava fatores ou cancelar"));
                continue;
            };
            if fatores.senha.is_none() {
                fatores.senha = atual.map(str::to_string);
            }
            return Some(fatores);
        }
    }
}

/// A conta, esta máquina e a carteira, como a janela as mostra. O CPF e o
/// titular são da própria pessoa: este é o canal dela, não um registro.
pub fn visao(estado: &Estado, agora: u64) -> Value {
    let cartoes: Vec<Value> = carteira::montar(estado, agora)
        .map(|c| c.cartoes)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let sessao = match c.sessao {
                Sessao::Aberta { ate } => json!({ "aberta": true, "ate": ate }),
                Sessao::Fechada => json!({ "aberta": false }),
            };
            // O DER em base64, para quem expõe o certificado (um token virtual).
            let der = achar(estado, &c.chave).and_then(|x| x.base64.clone());
            json!({
                "chave": c.chave,
                "titular": c.nome,
                "tipo": c.documento.as_ref().map(|d| d.tipo()),
                "documento": c.documento.as_ref().map(|d| d.formatado()),
                "emissor": c.emissor,
                "serie": c.serie,
                "validade": c.validade,
                "dias_restantes": c.dias_restantes(agora),
                "ativo": c.ativo,
                "sessao": sessao,
                "cadeia": c.autoridades,
                "certificado": der,
            })
        })
        .collect();
    json!({
        "preparado": estado.preparado(),
        "conta": estado.email.as_ref().map(|email| json!({
            "email": email,
            "nome": estado.nome,
        })),
        "computador": estado.nome_desktop,
        "celular_pareado": estado.celular_pareado,
        "certificados": cartoes,
    })
}

/// O certificado da carteira com esta chave ou este número de série.
pub fn achar<'a>(estado: &'a Estado, chave_ou_serie: &str) -> Option<&'a Certificado> {
    estado
        .certificados
        .iter()
        .find(|c| c.chave() == chave_ou_serie || c.serial_number == chave_ou_serie)
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Conversa com um cliente até ele fechar. `motor` é aberto uma vez por
/// conversa e relê o estado antes de cada pedido, porque o módulo PKCS#11 e a
/// janela podem tê-lo mudado.
pub fn atender(motor: Result<Motor, Erro>, leitura: impl BufRead, escrita: impl Write) {
    let canal = Canal {
        leitura: RefCell::new(leitura),
        escrita: RefCell::new(escrita),
    };
    let mut motor = match motor {
        Ok(m) => m,
        Err(e) => {
            canal.escrever(&json!({
                "id": Value::Null,
                "erro": { "tipo": e.tipo(), "mensagem": e.to_string() },
            }));
            return;
        }
    };
    while let Some(linha) = canal.ler() {
        let resposta = match serde_json::from_str::<Linha>(&linha) {
            Err(_) => erro(&Value::Null, PEDIDO_INVALIDO, "JSON inválido"),
            Ok(Linha { id, resto }) => match serde_json::from_value::<Operacao>(resto) {
                Err(e) => erro(&id, PEDIDO_INVALIDO, &e.to_string()),
                Ok(op) => match executar(&mut motor, op, &id, &canal) {
                    Ok(ok) => json!({ "id": id, "ok": ok }),
                    Err(Falha::Pedido(m)) => erro(&id, PEDIDO_INVALIDO, &m),
                    Err(Falha::Motor(e)) => erro(&id, &e.tipo(), &e.to_string()),
                },
            },
        };
        if !canal.escrever(&resposta) {
            return;
        }
    }
}

enum Falha {
    Pedido(String),
    Motor(Erro),
}

impl From<Erro> for Falha {
    fn from(e: Erro) -> Falha {
        Falha::Motor(e)
    }
}

fn executar<R: BufRead, W: Write>(
    motor: &mut Motor,
    op: Operacao,
    id: &Value,
    canal: &Canal<R, W>,
) -> Result<Value, Falha> {
    motor.recarregar()?;
    match op {
        Operacao::Estado => Ok(visao(&motor.estado, agora())),
        Operacao::Atualizar => {
            // O celular só informa: sem ele, a carteira ainda vale.
            let _ = motor.atualizar_celular();
            motor.atualizar_carteira()?;
            Ok(visao(&motor.estado, agora()))
        }
        Operacao::Entrar { email, senha, pin } => {
            let senha = Zeroizing::new(senha);
            let pin = pin.map(Zeroizing::new);
            if let Some(pin) = &pin
                && !pin::valido(pin)
            {
                return Err(Falha::Pedido(format!(
                    "o PIN local tem de {} a {} dígitos",
                    pin::MIN_DIGITOS,
                    pin::MAX_DIGITOS
                )));
            }
            let (nome, usuario) = crate::desta_maquina();
            let maquina = Maquina {
                nome: &nome,
                usuario_local: &usuario,
                dominio_rede: &nome,
            };
            let chaveiro = motor.preparar(&email, &senha, &maquina)?;
            let com_pin = match (&pin, chaveiro) {
                (Some(pin), false) => {
                    motor.proteger_com_pin(&senha, pin)?;
                    true
                }
                _ => false,
            };
            Ok(json!({ "chaveiro": chaveiro, "pin": com_pin }))
        }
        Operacao::Usar { certificado } => {
            let chave = achar(&motor.estado, &certificado)
                .map(Certificado::chave)
                .ok_or(Erro::NaoPreparado("o certificado não está na carteira"))?;
            motor.escolher_certificado(&chave)?;
            Ok(visao(&motor.estado, agora()))
        }
        Operacao::Reautorizar => {
            motor.reautorizar_proxima()?;
            Ok(Value::Null)
        }
        Operacao::Sair => {
            motor.sair()?;
            Ok(Value::Null)
        }
        Operacao::Assinar {
            formato,
            hash,
            documento,
            digest_info,
            certificado,
        } => {
            // O que vai ao motor: o SHA-256 (com o documento, no anexado) ou,
            // no cru, um DigestInfo pronto.
            enum Entrada {
                Resumo([u8; 32], Option<Vec<u8>>),
                DigestInfo(Vec<u8>),
            }
            let entrada = match (digest_info, hash, documento) {
                (Some(_), _, _) if formato != Formato::Cru => {
                    return Err(Falha::Pedido("digest_info é só do formato cru".into()));
                }
                (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                    return Err(Falha::Pedido(
                        "digest_info, hash ou documento: só um deles".into(),
                    ));
                }
                (Some(texto), None, None) => Entrada::DigestInfo(
                    de_b64(&texto)
                        .ok_or_else(|| Falha::Pedido("digest_info não é base64".into()))?,
                ),
                (None, Some(_), Some(_)) => {
                    return Err(Falha::Pedido("hash ou documento, não os dois".into()));
                }
                (None, Some(_), None) if formato == Formato::Anexado => {
                    return Err(Falha::Pedido(
                        "anexado precisa do documento, e o hash é só o resumo".into(),
                    ));
                }
                (None, Some(hex), None) => Entrada::Resumo(
                    de_hex(&hex).ok_or_else(|| {
                        Falha::Pedido("hash quer 64 dígitos hexadecimais (SHA-256)".into())
                    })?,
                    None,
                ),
                (None, None, Some(texto)) => {
                    let bytes = de_b64(&texto)
                        .ok_or_else(|| Falha::Pedido("documento não é base64".into()))?;
                    let digest = sha256(&bytes);
                    Entrada::Resumo(digest, (formato == Formato::Anexado).then_some(bytes))
                }
                (None, None, None) => {
                    return Err(Falha::Pedido("falta o hash ou o documento".into()));
                }
            };
            let certificado = match certificado {
                Some(c) => achar(&motor.estado, &c).cloned(),
                None => motor.estado.certificado().cloned(),
            }
            .ok_or(Erro::NaoPreparado("o certificado não está na carteira"))?;
            let autorizador = PeloCanal { id, canal };
            let assinatura = match (formato, entrada) {
                (_, Entrada::DigestInfo(bloco)) => {
                    motor.assinar_com(&certificado, Algoritmo::Cru, &bloco, &autorizador)?
                }
                (Formato::Cru, Entrada::Resumo(digest, _)) => {
                    motor.assinar_com(&certificado, Algoritmo::Sha256, &digest, &autorizador)?
                }
                (_, Entrada::Resumo(digest, anexar)) => {
                    cades::assinar_com(motor, &certificado, &digest, anexar, agora(), &autorizador)?
                }
            };
            Ok(json!({ "assinatura": b64(&assinatura) }))
        }
    }
}
