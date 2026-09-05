//! O serviço: trata uma [`Requisicao`], devolve uma [`Resposta`].
//!
//! Desacoplado do transporte (o socket UNIX está em [`crate::socket`]) para
//! que os testes de integração exercitem o fluxo otimista chamando
//! [`Servico::tratar`] direto, sem TCP nem UNIX. O `socket` é fino sobre isto.

use std::sync::atomic::{AtomicBool, Ordering};

use remoteid_aplicacao::{Algoritmo, Motor, Opcoes};
use remoteid_cripto::{b64, de_b64};
use remoteid_tipos::{Error, Origem};

use crate::prompter::{Contexto, Prompter};
use crate::protocolo::{
    CertificadoResumo, CodigoErro, Requisicao, Resposta, SessaoResumo, SucessoResposta,
};

pub struct Servico {
    motor: Motor,
    opcoes_base: Opcoes,
    prompter: Box<dyn Prompter>,
    encerrar: AtomicBool,
}

impl Servico {
    /// Abre o motor com as `opcoes` dadas e liga o `prompter` para
    /// solicitações interativas. O `Opcoes` é guardado para o
    /// [`Requisicao::Reinstalar`] poder reabrir do zero.
    pub fn novo(opcoes: Opcoes, prompter: Box<dyn Prompter>) -> remoteid_tipos::Result<Servico> {
        let opcoes_base = clonar_opcoes(&opcoes);
        let motor = Motor::abrir(opcoes)?;
        Ok(Servico {
            motor,
            opcoes_base,
            prompter,
            encerrar: AtomicBool::new(false),
        })
    }

    pub fn deve_encerrar(&self) -> bool {
        self.encerrar.load(Ordering::Relaxed)
    }

    /// Reabre o motor a partir das `opcoes_base`, relendo o `state.json` do
    /// disco. O app chama isto depois do wizard de preparação (que roda o CLI
    /// `remoteid preparar` num processo separado e grava o estado): sem
    /// reabrir, o `Servico` seguiria com o motor vazio de antes do preparo.
    /// Preserva o prompter e o cache — só o motor é trocado.
    pub fn reabrir(&mut self) -> remoteid_tipos::Result<()> {
        self.motor = Motor::abrir(clonar_opcoes(&self.opcoes_base))?;
        Ok(())
    }

    pub fn tratar(&mut self, req: Requisicao) -> Resposta {
        match req {
            Requisicao::Sign {
                algoritmo,
                digest_b64,
                hospedeiro,
            } => self.tratar_sign(algoritmo, digest_b64, hospedeiro),
            Requisicao::Status => self.tratar_status(),
            Requisicao::ReautorizarProxima => self.tratar_reautorizar(),
            Requisicao::EscolherCertificado { key_name } => self.tratar_escolher(key_name),
            Requisicao::Reinstalar => self.tratar_reinstalar(),
            Requisicao::Encerrar => {
                self.encerrar.store(true, Ordering::Relaxed);
                Resposta::Sucesso(SucessoResposta::Ack { ok: true })
            }
        }
    }

    fn tratar_sign(
        &mut self,
        algoritmo: Option<String>,
        digest_b64: String,
        hospedeiro: Option<String>,
    ) -> Resposta {
        // A borda: a string opaca do socket vira o tipo do domínio. Ausente é
        // o padrão (SHA256, o módulo de antes do modo cru); desconhecido é
        // entrada inválida, nunca um chute.
        let algoritmo = match algoritmo.as_deref() {
            None => Algoritmo::default(),
            Some(nome) => match Algoritmo::do_nome(nome) {
                Some(a) => a,
                None => {
                    return Resposta::falha(
                        CodigoErro::EntradaInvalida,
                        format!("algoritmo desconhecido: {nome:?}"),
                    );
                }
            },
        };
        let dados = match de_b64(&digest_b64) {
            Ok(d) => d,
            Err(e) => {
                return Resposta::falha(
                    CodigoErro::EntradaInvalida,
                    format!("digest_b64 não é base64 válido: {e}"),
                );
            }
        };
        // O tamanho do bloco é regra do `Algoritmo`, conferida pelo motor antes
        // de tocar o cache ou pedir PIN: um `Error::Uso` de lá vira
        // `EntradaInvalida` em `erro_para_resposta`.
        // Se `hospedeiro` não veio na mensagem, a camada de socket já teve a
        // chance de preencher com `SO_PEERCRED`; se ainda é `None`, deixa
        // como está (o diag registra "hospedeiro desconhecido"). Ver o TODO
        // no `crate::socket`.
        // O titular vem do login (`Estado::nome`) — é o que o diálogo GTK
        // mostra em "Assinar como <nome>". Só é útil quando já preparado;
        // se ainda não houver nome, o prompter cai no título genérico.
        let contexto = Contexto {
            hospedeiro: hospedeiro.clone(),
            titular: self.motor.estado.nome.clone(),
        };

        // Discriminador do `cache_hit`: comparamos o TOKEN cached antes e
        // depois. Se é o mesmo string, foi hit puro (o motor não tocou no
        // cache). Se mudou (ou sumiu), houve retry silencioso. Usar o
        // token e não o `visto_em` evita o falso positivo quando primeira e
        // segunda operação caem no mesmo segundo — o `agora()` do state
        // tem resolução de segundos.
        let cert_key = match self.motor.estado.certificado() {
            Ok(c) => c.chave_cache(),
            Err(_) => return Resposta::falha(CodigoErro::NaoPreparado, "sem certificado"),
        };
        let token_antes = self
            .motor
            .estado
            .sessoes
            .get(&cert_key)
            .map(|s| s.token.clone());

        let prompter = &*self.prompter;
        let resultado = self
            .motor
            .assinar_com_cache(algoritmo, &dados, || prompter.pedir_pin_otp(&contexto));

        match resultado {
            Ok(bytes) => {
                let token_depois = self
                    .motor
                    .estado
                    .sessoes
                    .get(&cert_key)
                    .map(|s| s.token.clone());
                let cache_hit = matches!(
                    (&token_antes, &token_depois),
                    (Some(a), Some(b)) if a == b
                );
                Resposta::Sucesso(SucessoResposta::Sign {
                    ok: true,
                    assinatura_b64: b64(&bytes),
                    cache_hit,
                })
            }
            Err(erro) => erro_para_resposta(erro),
        }
    }

    fn tratar_status(&self) -> Resposta {
        let e = &self.motor.estado;
        let certificados: Vec<CertificadoResumo> = e
            .certificados
            .iter()
            .map(|c| {
                let (validade, ous) = extrair_validade_e_ous(&c.issue, c.base64.as_deref());
                CertificadoResumo {
                    key_name: c.key_name.clone(),
                    serial_number: c.serial_number.clone(),
                    issue: c.issue.clone(),
                    ous,
                    validade,
                }
            })
            .collect();
        let sessoes: Vec<SessaoResumo> = e
            .sessoes
            .iter()
            .map(|(k, s)| SessaoResumo {
                cert_key: k.clone(),
                emitido_em: s.emitido_em,
                visto_em: s.visto_em,
            })
            .collect();
        Resposta::Sucesso(SucessoResposta::Status {
            ok: true,
            preparado: e.codigo_desktop.is_some() && !e.certificados.is_empty(),
            codigo_desktop: e.codigo_desktop.clone(),
            titular: e.nome.clone(),
            certificados,
            certificado_ativo: e.certificado_ativo().map(str::to_string),
            sessoes,
        })
    }

    /// Escolhe o certificado padrão e persiste. A próxima assinatura usa ele.
    fn tratar_escolher(&mut self, key_name: String) -> Resposta {
        self.motor.estado.definir_certificado_ativo(key_name);
        match self.motor.salvar_estado() {
            Ok(()) => Resposta::Sucesso(SucessoResposta::Ack { ok: true }),
            Err(e) => erro_para_resposta(e),
        }
    }

    fn tratar_reautorizar(&mut self) -> Resposta {
        match self.motor.reautorizar_proxima() {
            Ok(()) => Resposta::Sucesso(SucessoResposta::Ack { ok: true }),
            Err(Error::Estado(_)) => {
                // Sem certificado carregado: tratamos como "já não havia
                // sessão pra invalidar", que é semanticamente equivalente.
                Resposta::Sucesso(SucessoResposta::Ack { ok: true })
            }
            Err(e) => erro_para_resposta(e),
        }
    }

    fn tratar_reinstalar(&mut self) -> Resposta {
        let dir = self.opcoes_base.dir_dados.clone();
        // Não apagar o dir de diag: o log é auditoria, e apagá-lo esconde
        // exatamente o rastro que o usuário pode precisar depois. Só o
        // dir de DADOS some.
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Resposta::falha(
                    CodigoErro::ErroInterno,
                    format!("falha ao remover {}: {e}", dir.display()),
                );
            }
        }
        // Reabre com um motor VAZIO. `Motor::abrir` regenera a chave da
        // instalação (é o que `carregar_ou_gerar` faz) e retorna um Estado
        // padrão. A próxima operação de assinatura vai devolver
        // NAO_PREPARADO, que a janela vai empurrar pro wizard.
        match Motor::abrir(clonar_opcoes(&self.opcoes_base)) {
            Ok(m) => {
                self.motor = m;
                Resposta::Sucesso(SucessoResposta::Ack { ok: true })
            }
            Err(e) => erro_para_resposta(e),
        }
    }
}

fn erro_para_resposta(erro: Error) -> Resposta {
    match erro {
        Error::Uso(msg) if msg.contains("cancelado") => Resposta::falha(CodigoErro::Cancelado, msg),
        Error::Uso(msg) => Resposta::falha(CodigoErro::EntradaInvalida, msg),
        Error::Estado(msg) => Resposta::falha(CodigoErro::NaoPreparado, msg),
        Error::Rede(msg) => Resposta::falha(CodigoErro::ErroRede, msg),
        Error::Servidor(se) => {
            let com_hint = match se.hint {
                Some(h) => format!("{} — {h}", se.message),
                None => se.message.clone(),
            };
            let codigo = match se.origem {
                Origem::Usuario => CodigoErro::EntradaInvalida,
                _ => CodigoErro::ErroServidor,
            };
            Resposta::falha(codigo, com_hint)
        }
        outro => Resposta::falha(CodigoErro::ErroInterno, outro.to_string()),
    }
}

fn clonar_opcoes(o: &Opcoes) -> Opcoes {
    Opcoes {
        dir_dados: o.dir_dados.clone(),
        dir_diag: o.dir_diag.clone(),
        remoteid_url: o.remoteid_url.clone(),
        certinext_url: o.certinext_url.clone(),
        timeout: o.timeout,
        ttl_sessao_hipotetico_s: o.ttl_sessao_hipotetico_s,
    }
}

fn extrair_validade_e_ous(issue: &str, base64_der: Option<&str>) -> (Option<String>, Vec<String>) {
    let mut ous = Vec::new();
    let mut validade = None;

    if let Some(b64) = base64_der {
        if let Ok(der) = remoteid_cripto::de_b64(b64) {
            use der::Decode;
            if let Ok(cert) = x509_cert::Certificate::from_der(&der) {
                let not_after = cert.tbs_certificate.validity.not_after.to_date_time();
                validade = Some(format!(
                    "{:02}/{:02}/{:04}",
                    not_after.day(),
                    not_after.month(),
                    not_after.year()
                ));

                let subject_str = cert.tbs_certificate.subject.to_string();
                for parte in subject_str.split(',') {
                    let p = parte.trim();
                    if let Some(ou) = p.strip_prefix("OU=") {
                        let val = ou.trim().to_string();
                        if !val.is_empty() && !ous.contains(&val) {
                            ous.push(val);
                        }
                    }
                }
            }
        }
    }

    if ous.is_empty() {
        for parte in issue.split(',') {
            let p = parte.trim();
            if let Some(ou) = p.strip_prefix("OU=") {
                let val = ou.trim().to_string();
                if !val.is_empty() && !ous.contains(&val) {
                    ous.push(val);
                }
            }
        }
    }

    (validade, ous)
}
