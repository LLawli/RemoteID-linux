//! A chave RSA desta instalação e o base64 do protocolo.
//!
//! A chave não é a do certificado (essa vive no HSM da Certisign): é a que o
//! registro do desktop entrega ao servidor, e que assina o `Bearer` de cada
//! requisição de operação.

use std::fs;
use std::io;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::estado::gravar_privado;

/// Base64 padrão, com padding: o que o protocolo usa em todo lugar.
pub fn b64(dados: &[u8]) -> String {
    STANDARD.encode(dados)
}

/// O inverso de [`b64`]. Ignora espaço nas pontas, que o servidor às vezes
/// deixa.
pub fn de_b64(texto: &str) -> Option<Vec<u8>> {
    STANDARD.decode(texto.trim()).ok()
}

/// Um SHA-256 em hexadecimal, como `sha256sum` o escreve.
pub fn de_hex(texto: &str) -> Option<[u8; 32]> {
    let texto = texto.trim();
    if texto.len() != 64 || !texto.is_ascii() {
        return None;
    }
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&texto[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(bytes)
}

pub fn sha256(dados: &[u8]) -> [u8; 32] {
    Sha256::digest(dados).into()
}

/// O tamanho da chave da instalação, o mesmo do app oficial.
const BITS: usize = 2048;

pub struct ChaveInstalacao(RsaPrivateKey);

impl ChaveInstalacao {
    /// Lê uma chave PKCS#8 em PEM.
    pub fn de_pem(pem: &str) -> Option<ChaveInstalacao> {
        RsaPrivateKey::from_pkcs8_pem(pem).ok().map(ChaveInstalacao)
    }

    /// A chave gravada em `caminho`, ou uma nova, gravada ali com 0600.
    ///
    /// Trocar a chave desfaz o registro: o servidor só aceita o `Bearer` da
    /// chave pública que recebeu. Por isso um arquivo ilegível é erro, e não
    /// motivo para gerar outra por cima.
    pub fn carregar_ou_gerar(caminho: &Path) -> io::Result<ChaveInstalacao> {
        match fs::read_to_string(caminho) {
            Ok(pem) => ChaveInstalacao::de_pem(&pem).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} não é uma chave PKCS#8", caminho.display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let chave =
                    RsaPrivateKey::new(&mut rand::thread_rng(), BITS).map_err(io::Error::other)?;
                let pem = chave
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(io::Error::other)?;
                gravar_privado(caminho, pem.as_bytes())?;
                Ok(ChaveInstalacao(chave))
            }
            Err(e) => Err(e),
        }
    }

    /// A chave pública em PEM completo, com as linhas BEGIN e END: é o que o
    /// registro exige. Base64 do DER cru é recusado com ConstraintViolation.
    pub fn publica_pem(&self) -> String {
        RsaPublicKey::from(&self.0)
            .to_public_key_pem(LineEnding::LF)
            .expect("uma chave RSA válida sempre vira PEM")
    }

    /// O `Bearer` de uma requisição de operação: RSA PKCS#1 v1.5 sobre o
    /// SHA-256 da forma canônica do corpo, em base64.
    pub fn bearer(&self, canonica: &str) -> String {
        let assinatura = self
            .0
            .sign(Pkcs1v15Sign::new::<Sha256>(), &sha256(canonica.as_bytes()))
            .expect("assinar um SHA-256 com RSA-2048 não falha");
        b64(&assinatura)
    }
}
