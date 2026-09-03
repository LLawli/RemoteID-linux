//! PKCS#7 / CMS SignedData em volta da assinatura crua do HSM.
//!
//! O `requestHashSessionSignature` devolve 256 bytes de RSA cru. Isso é o que o
//! `C_Sign` do PKCS#11 precisa, mas não é o que um assinador de PDF ou um
//! validador de documento aceita: eles querem um CMS SignedData (`.p7s`).
//!
//! # A pegadinha central: não se assina o digest do documento
//!
//! É intuitivo pensar "tenho o SHA-256 do arquivo, mando assinar, embrulho".
//! **Está errado.** Num CMS com atributos assinados — que é o caso de qualquer
//! assinatura com hora, e de CAdES/ICP-Brasil sempre — a assinatura cobre o DER
//! do conjunto `signedAttrs`, e é *dentro* dele que vai o digest do documento,
//! no atributo `messageDigest` (RFC 5652 §5.4).
//!
//! ```text
//! documento ──SHA-256──> messageDigest ─┐
//!                                       ├─> signedAttrs ──SHA-256──> AO HSM
//! contentType, signingTime, signingCert ┘
//! ```
//!
//! Quem manda o digest do documento para o HSM produz um `.p7s` cuja assinatura
//! não fecha com nada, e o validador só diz "assinatura inválida" — sem dizer
//! que o erro foi assinar a coisa errada. Por isso este módulo é de duas fases:
//! [`Montador::digest_a_assinar`] devolve o que vai para o HSM, e
//! [`Montador::finalizar`] recebe a resposta. A chamada de rede fica no meio,
//! onde ela pertence, e o motor continua sem saber o que é CMS.
//!
//! # O que é incluído, e por quê
//!
//! Quatro atributos assinados:
//!
//! | atributo | por quê |
//! |---|---|
//! | `contentType` | obrigatório quando há atributos assinados (RFC 5652 §5.3) |
//! | `messageDigest` | idem; é onde mora o digest do documento |
//! | `signingTime` | a hora alegada pelo signatário |
//! | `signingCertificateV2` | amarra a assinatura a ESTE certificado |
//!
//! O `signingCertificateV2` (RFC 5035) é o que separa "um `.p7s` que o OpenSSL
//! aceita" de "um `.p7s` que um validador ICP-Brasil aceita": sem ele a
//! assinatura não é CAdES-BES, e o Verificador de Conformidade do ITI recusa.
//! Ele carrega o hash do certificado e o par emissor+série, de modo que trocar
//! o certificado do envelope invalida a assinatura.
//!
//! # Destacada por padrão
//!
//! Sem `eContent`: o documento não vai dentro do `.p7s`. É o que PAdES exige (o
//! conteúdo é o PDF em volta) e o que `openssl smime -sign -detached` produz.
//! Anexar é possível e serve para arquivo pequeno que deva viajar junto.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignatureValue, SignedAttributes, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode, Sequence};
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::crypto::sha256;
use crate::error::{Error, Result};

// Os OIDs vão literais em vez de virem do banco do `const_oid`: são oito, não
// mudam nunca, e escritos aqui dá para conferir cada um contra a RFC sem sair
// do arquivo.
/// id-data — RFC 5652 §4
const OID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// id-signedData — RFC 5652 §5.1
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-contentType — RFC 5652 §11.1
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// id-messageDigest — RFC 5652 §11.2
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// id-signingTime — RFC 5652 §11.3
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// id-aa-signingCertificateV2 — RFC 5035 §3
const OID_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// id-sha256 — RFC 5754
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// rsaEncryption — RFC 5754 §3.2 manda usar este, e não sha256WithRSAEncryption,
/// no campo `signatureAlgorithm` de um SignerInfo.
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `IssuerSerial` — RFC 5035 §4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct IssuerSerial {
    issuer: GeneralNames,
    serial_number: SerialNumber,
}

/// `ESSCertIDv2` — RFC 5035 §4
///
/// O campo `hashAlgorithm` é `DEFAULT id-sha256` e por isso está AUSENTE aqui:
/// em DER, um campo igual ao default tem de ser omitido, não escrito. Escrevê-lo
/// geraria um DER inválido que alguns validadores recusam.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
    issuer_serial: Option<IssuerSerial>,
}

/// `SigningCertificateV2` — RFC 5035 §3. O campo `policies` é opcional e omitido.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

/// Monta o CMS em duas fases, com a ida ao HSM no meio.
pub struct Montador {
    certificado: Certificate,
    atributos: SignedAttributes,
    /// `Some` quando o conteúdo vai DENTRO do envelope (assinatura anexada).
    conteudo: Option<Vec<u8>>,
    digest_a_assinar: [u8; 32],
}

impl Montador {
    /// Prepara o envelope para um documento cujo SHA-256 é `digest_conteudo`.
    ///
    /// `momento` é o epoch em segundos que vai no `signingTime`. `anexar`
    /// carrega o conteúdo para dentro do envelope; `None` produz a assinatura
    /// destacada, que é o padrão e o que PAdES exige.
    pub fn novo(
        cert_der: &[u8],
        digest_conteudo: &[u8],
        momento: u64,
        anexar: Option<Vec<u8>>,
    ) -> Result<Montador> {
        if digest_conteudo.len() != 32 {
            return Err(Error::uso(format!(
                "o digest do conteúdo tem de ser SHA-256 (32 bytes); veio com {}",
                digest_conteudo.len()
            )));
        }
        let certificado = Certificate::from_der(cert_der)
            .map_err(|e| Error::cripto(format!("certificado X.509 ilegível: {e}")))?;

        // Coerência: se o conteúdo vai anexado, o digest tem de ser o DELE.
        // Deixar os dois divergirem produz um envelope que só falha na
        // validação, longe da causa.
        if let Some(bytes) = &anexar {
            if sha256(bytes) != digest_conteudo {
                return Err(Error::uso(
                    "o digest informado não é o do conteúdo anexado",
                ));
            }
        }

        let atributos = montar_atributos(&certificado, digest_conteudo, momento)?;
        // É ISTO que vai para o HSM: o hash do DER dos atributos assinados,
        // não o hash do documento.
        let der = atributos
            .to_der()
            .map_err(|e| Error::cripto(format!("não serializou os atributos: {e}")))?;

        Ok(Montador {
            certificado,
            atributos,
            conteudo: anexar,
            digest_a_assinar: sha256(&der),
        })
    }

    /// O digest que deve ser mandado ao HSM. **Não** é o digest do documento.
    pub fn digest_a_assinar(&self) -> &[u8; 32] {
        &self.digest_a_assinar
    }

    /// Fecha o envelope com a assinatura devolvida pelo HSM. Devolve o DER.
    pub fn finalizar(self, assinatura: &[u8]) -> Result<Vec<u8>> {
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: self.certificado.tbs_certificate.issuer.clone(),
            serial_number: self.certificado.tbs_certificate.serial_number.clone(),
        });

        let signer_info = SignerInfo {
            // V1 é o exigido quando o signatário é identificado por
            // emissor+série (RFC 5652 §5.3).
            version: CmsVersion::V1,
            sid,
            digest_alg: alg_sha256(),
            signed_attrs: Some(self.atributos),
            signature_algorithm: alg_rsa(),
            signature: SignatureValue::new(assinatura)
                .map_err(|e| Error::cripto(format!("assinatura inválida para o envelope: {e}")))?,
            unsigned_attrs: None,
        };

        let econtent = match &self.conteudo {
            Some(bytes) => {
                let octetos = OctetString::new(bytes.as_slice())
                    .map_err(|e| Error::cripto(format!("conteúdo inválido: {e}")))?;
                Some(
                    Any::encode_from(&octetos)
                        .map_err(|e| Error::cripto(format!("não embrulhou o conteúdo: {e}")))?,
                )
            }
            None => None,
        };

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: conjunto(vec![alg_sha256()])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: OID_DATA,
                econtent,
            },
            // O certificado do signatário viaja junto: sem ele o validador não
            // tem a chave pública para conferir a assinatura.
            certificates: Some(CertificateSet(conjunto(vec![
                CertificateChoices::Certificate(self.certificado),
            ])?)),
            crls: None,
            signer_infos: SignerInfos(conjunto(vec![signer_info])?),
        };

        let content_info = ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::encode_from(&signed_data)
                .map_err(|e| Error::cripto(format!("não embrulhou o SignedData: {e}")))?,
        };
        content_info
            .to_der()
            .map_err(|e| Error::cripto(format!("não serializou o PKCS#7: {e}")))
    }
}

fn montar_atributos(
    certificado: &Certificate,
    digest_conteudo: &[u8],
    momento: u64,
) -> Result<SignedAttributes> {
    let mut attrs = Vec::new();
    attrs.push(atributo(OID_CONTENT_TYPE, &OID_DATA)?);
    attrs.push(atributo(
        OID_MESSAGE_DIGEST,
        &OctetString::new(digest_conteudo)
            .map_err(|e| Error::cripto(format!("messageDigest inválido: {e}")))?,
    )?);

    let hora = UtcTime::from_unix_duration(std::time::Duration::from_secs(momento))
        .map_err(|e| Error::cripto(format!("signingTime fora da faixa do UTCTime: {e}")))?;
    attrs.push(atributo(OID_SIGNING_TIME, &Time::UtcTime(hora))?);

    attrs.push(atributo(
        OID_SIGNING_CERT_V2,
        &signing_certificate_v2(certificado)?,
    )?);

    SignedAttributes::try_from(attrs)
        .map_err(|e| Error::cripto(format!("conjunto de atributos inválido: {e}")))
}

/// Amarra a assinatura a este certificado exato (RFC 5035).
fn signing_certificate_v2(certificado: &Certificate) -> Result<SigningCertificateV2> {
    let der = certificado
        .to_der()
        .map_err(|e| Error::cripto(format!("não reserializou o certificado: {e}")))?;
    let hash = sha256(&der);

    let issuer_serial = IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(
            certificado.tbs_certificate.issuer.clone(),
        )],
        serial_number: certificado.tbs_certificate.serial_number.clone(),
    };

    Ok(SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(hash)
                .map_err(|e| Error::cripto(format!("hash do certificado inválido: {e}")))?,
            issuer_serial: Some(issuer_serial),
        }],
    })
}

fn atributo<T: der::Tagged + der::EncodeValue>(
    oid: ObjectIdentifier,
    valor: &T,
) -> Result<Attribute> {
    let any: AttributeValue = Any::encode_from(valor)
        .map_err(|e| Error::cripto(format!("valor de atributo inválido: {e}")))?;
    Ok(Attribute {
        oid,
        values: conjunto(vec![any])?,
    })
}

/// `SET OF` em DER: os elementos saem ordenados pela própria codificação, o que
/// o `SetOfVec` já garante.
fn conjunto<T: der::DerOrd>(itens: Vec<T>) -> Result<SetOfVec<T>> {
    SetOfVec::try_from(itens).map_err(|e| Error::cripto(format!("SET OF inválido: {e}")))
}

fn alg_sha256() -> AlgorithmIdentifierOwned {
    // RFC 5754 §2: para SHA-2 os parâmetros devem ser OMITIDOS, não NULL.
    AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: None,
    }
}

fn alg_rsa() -> AlgorithmIdentifierOwned {
    // Aqui, ao contrário, os parâmetros são NULL explícito (RFC 3370 §3.2).
    AlgorithmIdentifierOwned {
        oid: OID_RSA,
        parameters: Some(Any::null()),
    }
}
