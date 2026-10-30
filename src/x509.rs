//! O pouco de X.509 que o RemoteID lê do certificado da carteira: os campos
//! que o token PKCS#11 publica e o nome do titular.

use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use x509_cert::Certificate;
use x509_cert::der::{self, Decode, Encode};
use x509_cert::name::Name;

use crate::cripto::sha256;

/// O OID do `commonName`.
const CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");

/// Os campos de um certificado, em DER, como o Cryptoki os quer.
pub struct Campos {
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    /// O DER do INTEGER, não o número em texto: o NSS compara byte a byte com
    /// o que extrai do certificado, e texto aqui faz o par certificado e chave
    /// nunca casar.
    pub serial: Vec<u8>,
    /// O que pareia o certificado com a chave. Só precisa ser estável e igual
    /// nos dois; sai do SPKI para não depender de o certificado trazer o
    /// SubjectKeyIdentifier, e dá a cada autoridade um id que não é o do
    /// titular.
    pub id: Vec<u8>,
    pub nome: Option<String>,
    /// O `CN` do emissor: a AC que assinou.
    pub emissor: Option<String>,
    /// O fim da validade (`notAfter`), em segundos desde 1970.
    pub validade: u64,
    /// `None` quando a chave não é RSA.
    pub publica: Option<RsaPublicKey>,
}

/// Quantos bytes do SHA-256 do SPKI viram o `CKA_ID`.
const BYTES_ID: usize = 20;

pub fn ler(der: &[u8]) -> Result<Campos, String> {
    let certificado = Certificate::from_der(der).map_err(|e| format!("X.509 inválido: {e}"))?;
    let tbs = &certificado.tbs_certificate;
    let codificar = |campo: &str, r: der::Result<Vec<u8>>| r.map_err(|e| format!("{campo}: {e}"));
    let spki = codificar("SPKI", tbs.subject_public_key_info.to_der())?;
    Ok(Campos {
        subject: codificar("subject", tbs.subject.to_der())?,
        issuer: codificar("issuer", tbs.issuer.to_der())?,
        serial: codificar("serial", tbs.serial_number.to_der())?,
        id: sha256(&spki)[..BYTES_ID].to_vec(),
        nome: nome_comum(&tbs.subject),
        emissor: nome_comum(&tbs.issuer),
        validade: tbs.validity.not_after.to_unix_duration().as_secs(),
        publica: RsaPublicKey::from_pkcs1_der(
            tbs.subject_public_key_info.subject_public_key.raw_bytes(),
        )
        .ok(),
    })
}

/// O `CN` do RDN mais específico, que no certificado do titular é o nome e o
/// CPF (`FULANO DE TAL:12345678901`).
fn nome_comum(nome: &Name) -> Option<String> {
    nome.0
        .iter()
        .rev()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atributo| atributo.oid == CN)
        .and_then(|atributo| std::str::from_utf8(atributo.value.value()).ok())
        .filter(|cn| !cn.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TITULAR: &[u8] = include_bytes!("../tests/mock/fake-cert.der");

    #[test]
    fn le_o_certificado_do_titular() {
        let campos = ler(TITULAR).unwrap();
        assert_eq!(campos.nome.as_deref(), Some("TESTE DESKTOPID:00000000000"));
        assert!(campos.publica.is_some());
        assert_eq!(campos.id.len(), BYTES_ID);
        // INTEGER em DER: tag 0x02 e o comprimento.
        assert_eq!(campos.serial[0], 0x02);
        assert_ne!(campos.subject, campos.issuer);
        assert_eq!(campos.emissor.as_deref(), Some("AC TESTE DESKTOPID"));
        assert_eq!(campos.validade, 2_103_823_054); // 2036-08-31 19:17:34 UTC
    }

    #[test]
    fn lixo_nao_e_certificado() {
        assert!(ler(b"lixo").is_err());
    }
}
