//! O harness: roda o fluxo com a conta já entrada e escreve um relatório para
//! enviar a quem investiga.
//!
//! Nenhuma falha o interrompe. Cada passo sai marcado, com o motivo, e o que
//! dependia de um passo quebrado sai pulado: "parou aqui, a Certisign
//! respondeu isto" vale mais que um código de saída.
//!
//! O relatório não traz senha, PIN, OTP, token, e-mail nem o nome do titular;
//! aponta para o diagnóstico desta execução, que já passou pela redação.
//! Gasta um OTP: a assinatura de teste abre uma sessão quando não há uma em
//! cache.

use std::cell::Cell;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rsa::pkcs1v15::Pkcs1v15Sign;
use sha2::Sha256;

use crate::cades::{AD_RB, Montador};
use crate::cripto::{de_b64, sha256};
use crate::estado::gravar_privado;
use crate::motor::{Autorizador, Credencial, Fatores, Motor};
use crate::protocolo::{Algoritmo, Certificado};
use crate::x509;

/// O que a assinatura de teste assina: fixo, para os relatórios se compararem.
pub const MENSAGEM: &[u8] = b"RemoteID harness teste";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marca {
    Ok,
    Falha,
    Pulado,
}

impl Marca {
    fn simbolo(self) -> &'static str {
        match self {
            Marca::Ok => "[ok]",
            Marca::Falha => "[XX]",
            Marca::Pulado => "[  ]",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Passo {
    pub rotulo: &'static str,
    pub marca: Marca,
    pub detalhe: String,
}

impl std::fmt::Display for Passo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.marca.simbolo(), self.rotulo)?;
        if !self.detalhe.is_empty() {
            write!(f, ": {}", self.detalhe)?;
        }
        Ok(())
    }
}

pub struct Relatorio {
    pub inicio: u64,
    pub passos: Vec<Passo>,
    /// O diagnóstico JSONL desta execução.
    pub diagnostico: Option<PathBuf>,
}

impl Relatorio {
    pub fn falhou(&self) -> bool {
        self.passos.iter().any(|p| p.marca != Marca::Ok)
    }

    pub fn texto(&self) -> String {
        let mut t = format!(
            "RemoteID {} harness\ninício: {} (epoch)\n\n",
            env!("CARGO_PKG_VERSION"),
            self.inicio
        );
        for p in &self.passos {
            let _ = writeln!(t, "{p}");
        }
        let _ = writeln!(
            t,
            "\ndiagnóstico: {}",
            self.diagnostico
                .as_deref()
                .map_or("não gravado".into(), |p| p.display().to_string())
        );
        t
    }

    /// Grava o relatório em `diretorio`, 0600, e devolve onde.
    pub fn salvar(&self, diretorio: &Path) -> std::io::Result<PathBuf> {
        let caminho = diretorio.join(format!("harness-{}.txt", self.inicio));
        gravar_privado(&caminho, self.texto().as_bytes())?;
        Ok(caminho)
    }
}

/// Roda os passos e avisa cada um a `mostrar`, à medida que terminam.
pub fn rodar(
    motor: &mut Motor,
    autorizador: &dyn Autorizador,
    momento: u64,
    diagnostico: Option<PathBuf>,
    mut mostrar: impl FnMut(&Passo),
) -> Relatorio {
    let mut passos = Vec::new();
    let mut anotar = |rotulo, marca, detalhe: String| {
        let passo = Passo {
            rotulo,
            marca,
            detalhe,
        };
        mostrar(&passo);
        passos.push(passo);
    };

    anotar("ambiente", Marca::Ok, ambiente());
    match motor.conectar() {
        Ok(()) => anotar("conectividade", Marca::Ok, String::new()),
        Err(e) => anotar("conectividade", Marca::Falha, format!("{e} ({e:?})")),
    }

    let preparado = motor.estado.preparado();
    if preparado {
        anotar("conta", Marca::Ok, "entrada e máquina registrada".into());
    } else {
        anotar(
            "conta",
            Marca::Falha,
            "não há conta entrada: abra o RemoteID e entre".into(),
        );
    }

    let carteira = preparado.then(|| motor.atualizar_carteira());
    let certificado = match carteira {
        None => {
            anotar("carteira", Marca::Pulado, String::new());
            None
        }
        Some(Err(e)) => {
            anotar("carteira", Marca::Falha, format!("{e} ({e:?})"));
            None
        }
        Some(Ok(())) => match motor.estado.certificado().cloned() {
            Some(c) => {
                let n = motor.estado.certificados.len();
                anotar(
                    "carteira",
                    Marca::Ok,
                    format!("{n} certificado(s); {}", resumo(&c)),
                );
                Some(c)
            }
            None => {
                anotar(
                    "carteira",
                    Marca::Falha,
                    "nenhum certificado na conta".into(),
                );
                None
            }
        },
    };

    match &certificado {
        None => anotar("cadeia", Marca::Pulado, String::new()),
        Some(c) if c.cadeia.is_empty() => anotar(
            "cadeia",
            Marca::Falha,
            "não baixada; o motivo está no diagnóstico".into(),
        ),
        Some(c) => anotar(
            "cadeia",
            Marca::Ok,
            format!("{} autoridade(s)", c.cadeia.len()),
        ),
    }

    match &certificado {
        None => {
            anotar("assinatura", Marca::Pulado, String::new());
            anotar("p7s", Marca::Pulado, String::new());
        }
        Some(c) => {
            let (assinatura, p7s) = assinar(motor, c, autorizador, momento);
            match assinatura {
                Ok(d) => anotar("assinatura", Marca::Ok, d),
                Err(d) => anotar("assinatura", Marca::Falha, d),
            }
            match p7s {
                None => anotar("p7s", Marca::Pulado, String::new()),
                Some(Ok(d)) => anotar("p7s", Marca::Ok, d),
                Some(Err(d)) => anotar("p7s", Marca::Falha, d),
            }
        }
    }

    Relatorio {
        inicio: momento,
        passos,
        diagnostico,
    }
}

fn ambiente() -> String {
    let flatpak = std::env::var("FLATPAK_ID").ok();
    format!(
        "versão {}; {}",
        env!("CARGO_PKG_VERSION"),
        flatpak.map_or("fora do Flatpak".into(), |id| format!("Flatpak {id}"))
    )
}

/// O emissor e a validade, sem o titular.
fn resumo(certificado: &Certificado) -> String {
    let Some(campos) = certificado
        .base64
        .as_deref()
        .and_then(de_b64)
        .and_then(|d| x509::ler(&d).ok())
    else {
        return "sem o DER do certificado".into();
    };
    format!(
        "emissor {}, vale até {} (epoch)",
        campos.emissor.as_deref().unwrap_or("?"),
        campos.validade
    )
}

/// Conta quantas vezes o motor pediu os fatores.
struct Contador<'a> {
    dentro: &'a dyn Autorizador,
    pedidos: Cell<u32>,
}

impl Autorizador for Contador<'_> {
    fn pedir(
        &self,
        certificado: &Certificado,
        recusa: Option<&str>,
        credencial: Credencial<'_>,
    ) -> Option<Fatores> {
        self.pedidos.set(self.pedidos.get() + 1);
        self.dentro.pedir(certificado, recusa, credencial)
    }
}

/// Assina [`MENSAGEM`] num `.p7s` destacado. A assinatura crua é conferida
/// contra a chave pública do certificado antes de o envelope fechar, e o
/// envelope é relido; uma falha no primeiro deixa o segundo `None`.
#[allow(clippy::type_complexity)]
fn assinar(
    motor: &mut Motor,
    certificado: &Certificado,
    autorizador: &dyn Autorizador,
    momento: u64,
) -> (Result<String, String>, Option<Result<String, String>>) {
    let Some(der) = certificado.base64.as_deref().and_then(de_b64) else {
        return (Err("a carteira não trouxe o certificado".into()), None);
    };
    let montador = match Montador::novo(&der, &sha256(MENSAGEM), momento, None, Some(&AD_RB)) {
        Ok(m) => m,
        Err(e) => return (Err(e.to_string()), None),
    };
    let contador = Contador {
        dentro: autorizador,
        pedidos: Cell::new(0),
    };
    let relogio = Instant::now();
    let assinatura = match motor.assinar_com(
        certificado,
        Algoritmo::Sha256,
        montador.a_assinar(),
        &contador,
    ) {
        Ok(a) => a,
        Err(e) => return (Err(format!("{e} ({e:?})")), None),
    };
    let tempo = relogio.elapsed().as_millis();
    // O estado não basta: uma sessão guardada que o servidor já esqueceu
    // está em cache e ainda assim pede os fatores.
    let sessao = match contador.pedidos.get() {
        0 => "sessão em cache".to_string(),
        n => format!("sessão nova, {n} pedido(s) dos fatores"),
    };
    let confere = x509::ler(&der).ok().and_then(|c| c.publica).map(|chave| {
        chave
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                montador.a_assinar(),
                &assinatura,
            )
            .is_ok()
    });
    match confere {
        Some(true) => {}
        Some(false) => {
            return (
                Err(format!(
                    "{sessao}, {tempo} ms; não confere com a chave do certificado"
                )),
                None,
            );
        }
        None => {
            return (
                Err(format!(
                    "{sessao}, {tempo} ms; o certificado não tem chave RSA"
                )),
                None,
            );
        }
    }
    let detalhe = format!(
        "{sessao}, {tempo} ms, {} bytes, confere com a chave do certificado",
        assinatura.len()
    );
    let p7s = montador
        .finalizar(&assinatura)
        .map_err(|e| e.to_string())
        .and_then(|p7s| {
            use der::Decode;
            cms::content_info::ContentInfo::from_der(&p7s)
                .map(|_| format!("AD-RB destacado, {} bytes", p7s.len()))
                .map_err(|e| format!("o envelope não relê: {e}"))
        });
    (Ok(detalhe), Some(p7s))
}
