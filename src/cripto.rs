//! A chave RSA desta instalação e o base64 do protocolo.
//!
//! A chave não é a do certificado (essa vive no HSM da Certisign): é a que o
//! registro do desktop entrega ao servidor, e que assina o `Bearer` de cada
//! requisição de operação.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Base64 padrão, com padding: o que o protocolo usa em todo lugar.
pub fn b64(dados: &[u8]) -> String {
    STANDARD.encode(dados)
}

/// O inverso de [`b64`]. Ignora espaço nas pontas, que o servidor às vezes
/// deixa.
pub fn de_b64(texto: &str) -> Option<Vec<u8>> {
    STANDARD.decode(texto.trim()).ok()
}

pub fn sha256(dados: &[u8]) -> [u8; 32] {
    Sha256::digest(dados).into()
}

pub struct ChaveInstalacao(RsaPrivateKey);

impl ChaveInstalacao {
    /// Lê uma chave PKCS#8 em PEM.
    pub fn de_pem(pem: &str) -> Option<ChaveInstalacao> {
        RsaPrivateKey::from_pkcs8_pem(pem).ok().map(ChaveInstalacao)
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
