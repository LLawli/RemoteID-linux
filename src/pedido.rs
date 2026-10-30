//! O pedido de PIN e OTP do módulo PKCS#11: o `remoteid pedir`, um processo
//! que vive o tempo da pergunta.
//!
//! O pedido vai pelo stdin e os fatores voltam pelo stdout, nunca por
//! argumento nem por ambiente, que outros processos leem em `/proc`. O stdout
//! do módulo também não serve: dentro do `p11-kit server` ele é o canal do
//! protocolo com o aplicativo, e o diálogo herdá-lo corromperia a conversa.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cripto::de_b64;
use crate::motor::{Autorizador, Fatores};
use crate::protocolo::Certificado;
use crate::x509;

/// O subcomando do `remoteid` que mostra o diálogo.
pub const SUBCOMANDO: &str = "pedir";

/// Troca o executável do diálogo. Os testes usam um que responde sozinho.
pub const ENV_DIALOGO: &str = "REMOTEID_DIALOGO";

/// Quanto a pessoa tem para responder antes de a assinatura desistir.
pub const LIMITE: Duration = Duration::from_secs(5 * 60);

/// O que o diálogo recebe.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Pedido {
    /// O nome do titular, como está no certificado.
    pub titular: Option<String>,
    /// Por que o servidor recusou a tentativa anterior.
    pub recusa: Option<String>,
}

pub struct Dialogo {
    executavel: PathBuf,
    limite: Duration,
}

impl Dialogo {
    pub fn novo(executavel: PathBuf, limite: Duration) -> Dialogo {
        Dialogo { executavel, limite }
    }

    /// O `remoteid` ao lado deste módulo, ou o de [`ENV_DIALOGO`].
    pub fn do_ambiente() -> Option<Dialogo> {
        let executavel = std::env::var_os(ENV_DIALOGO)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| vizinho(&biblioteca_atual()?))?;
        Some(Dialogo::novo(executavel, LIMITE))
    }

    fn perguntar(&self, pedido: &Pedido) -> Option<Fatores> {
        let mut filho = Command::new(&self.executavel)
            .arg(SUBCOMANDO)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut entrada = filho.stdin.take()?;
        let _ = entrada.write_all(&serde_json::to_vec(pedido).ok()?);
        drop(entrada);

        let mut saida = filho.stdout.take()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = saida.read_to_end(&mut bytes);
            let _ = tx.send(bytes);
        });
        let Ok(resposta) = rx.recv_timeout(self.limite) else {
            let _ = filho.kill();
            let _ = filho.wait();
            return None;
        };
        if !filho.wait().ok()?.success() {
            return None;
        }
        serde_json::from_slice(&resposta).ok()
    }
}

impl Autorizador for Dialogo {
    fn pedir(&self, certificado: &Certificado, recusa: Option<&str>) -> Option<Fatores> {
        let titular = certificado
            .base64
            .as_deref()
            .and_then(de_b64)
            .and_then(|der| x509::ler(&der).ok()?.nome);
        self.perguntar(&Pedido {
            titular,
            recusa: recusa.map(str::to_string),
        })
    }
}

/// O arquivo de onde este código foi carregado: o `libremoteid.so` dentro do
/// `p11-kit server`, ou o executável, fora dele.
fn biblioteca_atual() -> Option<PathBuf> {
    let endereco = biblioteca_atual as *const () as usize;
    let mapas = std::fs::read_to_string("/proc/self/maps").ok()?;
    mapas.lines().find_map(|linha| {
        let mut campos = linha.split_whitespace();
        let (inicio, fim) = campos.next()?.split_once('-')?;
        let dentro = usize::from_str_radix(inicio, 16).ok()? <= endereco
            && endereco < usize::from_str_radix(fim, 16).ok()?;
        let caminho = campos.nth(4)?;
        (dentro && caminho.starts_with('/')).then(|| PathBuf::from(caminho))
    })
}

/// O `remoteid` da mesma instalação: `bin/` ao lado de `lib/` na extensão, ou
/// o mesmo diretório num build do Cargo.
fn vizinho(biblioteca: &Path) -> Option<PathBuf> {
    let dir = biblioteca.parent()?;
    [dir.join("../bin/remoteid"), dir.join("remoteid")]
        .into_iter()
        .find(|c| c.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acha_o_proprio_arquivo_nos_mapas() {
        let atual = biblioteca_atual().unwrap();
        assert_eq!(atual, std::env::current_exe().unwrap());
    }
}
