//! O `.p7s`: um CMS SignedData em volta da assinatura que o HSM da Certisign
//! devolve, na política AD-RB da ICP-Brasil (CAdES-EPES).
//!
//! # Não se assina o digest do documento
//!
//! Num CMS com atributos assinados, o que é assinado é o DER do conjunto
//! `signedAttrs`, e o digest do documento vai dentro dele, no `messageDigest`
//! (RFC 5652 §5.4):
//!
//! ```text
//! documento ──SHA-256──> messageDigest ─┐
//!                                       ├─> signedAttrs ──SHA-256──> ao HSM
//! contentType, signingTime, signingCert, ┘
//! sigPolicyId
//! ```
//!
//! Mandar ao HSM o digest do documento dá um `.p7s` cuja assinatura não fecha
//! com nada, e o validador só diz "assinatura inválida". Por isso o
//! [`Montador`] tem duas fases, com a ida ao servidor no meio.
//!
//! # Os atributos
//!
//! | atributo | por quê |
//! |---|---|
//! | `contentType` | obrigatório com atributos assinados (RFC 5652 §5.3) |
//! | `messageDigest` | idem; é onde mora o digest do documento |
//! | `signingTime` | a hora alegada pelo signatário |
//! | `signingCertificateV2` | amarra a assinatura a este certificado (RFC 5035) |
//! | `sigPolicyId` | a política de assinatura ICP-Brasil ([`AD_RB`]) |
//!
//! A tabela A.2 do DOC-ICP-15.03 v9.0 e a própria AD-RB v2.4 exigem
//! `contentType`, `messageDigest`, `signingCertificateV2` e `sigPolicyId`, e
//! só o certificado do titular no envelope (`signerOnly`). O `signingTime` não
//! é exigido nem proibido no CAdES (o ND da tabela é do PAdES).
//!
//! Sem política, o envelope sai byte a byte igual ao do RemoteID-linux v0.3.2
//! (`tests/paridade/cades.json`), que não tinha o `sigPolicyId`. Destacado
//! por padrão, sem `eContent`, como o `openssl cms -sign` sem `-nodetach`;
//! anexar serve a arquivo pequeno que deva viajar junto.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignatureValue, SignedAttributes, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, Ia5String, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode, Sequence};
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use crate::cripto::{de_b64, sha256};
use crate::motor::{self, Autorizador, Motor};
use crate::protocolo::{Algoritmo, Certificado};

/// id-data, RFC 5652 §4
const OID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// id-signedData, RFC 5652 §5.1
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-contentType, RFC 5652 §11.1
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// id-messageDigest, RFC 5652 §11.2
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// id-signingTime, RFC 5652 §11.3
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// id-aa-signingCertificateV2, RFC 5035 §3
const OID_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// id-aa-ets-sigPolicyId, RFC 5126 §5.8.1
const OID_SIG_POLICY_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");
/// id-spq-ets-uri, RFC 5126 §5.8.1
const OID_SPQ_URI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.5.1");
/// id-sha256, RFC 5754
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// rsaEncryption: a RFC 5754 §3.2 manda este, e não sha256WithRSAEncryption,
/// no `signatureAlgorithm` de um SignerInfo.
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Uma política de assinatura da ICP-Brasil, como o `sigPolicyId` a cita.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Politica {
    pub oid: ObjectIdentifier,
    /// O hash interno da política (o `signPolicyHash`, o último campo do
    /// arquivo), em SHA-256. A Nota 2 do DOC-ICP-15.03 manda este, e não o
    /// hash do arquivo publicado na LPA.
    pub hash: [u8; 32],
    /// Onde baixar a política, no único `spuri` que a Nota 1 permite.
    pub uri: &'static str,
}

/// A AD-RB v2.4, vigente de 2025-06-12 a 2037-10-22 pela LPA, que aceita as
/// cadeias até a AC Raiz v5 e a v12. A cópia em `tests/icp-brasil/` prova o
/// hash.
pub const AD_RB: Politica = Politica {
    oid: ObjectIdentifier::new_unwrap("2.16.76.1.7.1.1.2.4"),
    hash: [
        0x1f, 0x3c, 0x90, 0x4c, 0x44, 0xc3, 0x92, 0xfe, 0xef, 0x44, 0x7e, 0x21, 0xfa, 0xa7, 0xa0,
        0x4e, 0x85, 0xd9, 0xc0, 0x15, 0x33, 0x46, 0x32, 0x0f, 0x55, 0x7b, 0x70, 0x42, 0xaf, 0x5d,
        0xcf, 0x13,
    ],
    uri: "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.der",
};

#[derive(Debug, PartialEq, Eq)]
pub enum Erro {
    /// O digest do documento não tem 32 bytes.
    Digest(usize),
    /// O conteúdo anexado não é o do digest informado.
    ConteudoDiverge,
    /// O certificado não é um X.509 legível.
    Certificado(String),
    /// Algum campo não coube no DER.
    Der(String),
}

impl std::fmt::Display for Erro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Erro::Digest(n) => write!(f, "o digest tem de ser SHA-256 (32 bytes), veio com {n}"),
            Erro::ConteudoDiverge => f.write_str("o digest não é o do conteúdo anexado"),
            Erro::Certificado(e) => write!(f, "certificado ilegível: {e}"),
            Erro::Der(e) => write!(f, "envelope inválido: {e}"),
        }
    }
}

fn der(e: der::Error) -> Erro {
    Erro::Der(e.to_string())
}

/// `IssuerSerial`, RFC 5035 §4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct IssuerSerial {
    issuer: GeneralNames,
    serial_number: SerialNumber,
}

/// `ESSCertIDv2`, RFC 5035 §4. O `hashAlgorithm` é `DEFAULT id-sha256` e por
/// isso fica ausente: em DER, um campo igual ao default é omitido.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
    issuer_serial: Option<IssuerSerial>,
}

/// `SigningCertificateV2`, RFC 5035 §3, sem `policies`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

/// `OtherHashAlgAndValue`, RFC 5126 §5.8.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OtherHashAlgAndValue {
    hash_algorithm: AlgorithmIdentifierOwned,
    hash_value: OctetString,
}

/// `SigPolicyQualifierInfo`, RFC 5126 §5.8.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SigPolicyQualifierInfo {
    sig_policy_qualifier_id: ObjectIdentifier,
    sig_qualifier: Any,
}

/// `SignaturePolicyId`, RFC 5126 §5.8.1: a escolha explícita do
/// `SignaturePolicyIdentifier`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SignaturePolicyId {
    sig_policy_id: ObjectIdentifier,
    sig_policy_hash: OtherHashAlgAndValue,
    sig_policy_qualifiers: Option<Vec<SigPolicyQualifierInfo>>,
}

/// Monta o CMS em duas fases, com a ida ao HSM no meio.
pub struct Montador {
    certificado: Certificate,
    atributos: SignedAttributes,
    /// `Some` quando o conteúdo vai dentro do envelope.
    conteudo: Option<Vec<u8>>,
    a_assinar: [u8; 32],
}

impl Montador {
    /// Prepara o envelope de um documento cujo SHA-256 é `digest`. `momento`
    /// é o `signingTime`, em segundos desde 1970; `anexar` leva o conteúdo
    /// para dentro; `politica` acrescenta o `sigPolicyId`.
    pub fn novo(
        certificado: &[u8],
        digest: &[u8],
        momento: u64,
        anexar: Option<Vec<u8>>,
        politica: Option<&Politica>,
    ) -> Result<Montador, Erro> {
        if digest.len() != 32 {
            return Err(Erro::Digest(digest.len()));
        }
        let certificado =
            Certificate::from_der(certificado).map_err(|e| Erro::Certificado(e.to_string()))?;
        // Um digest que não é o do conteúdo anexado só falharia na validação,
        // longe da causa.
        if anexar.as_ref().is_some_and(|c| sha256(c) != digest) {
            return Err(Erro::ConteudoDiverge);
        }
        let atributos = atributos(&certificado, digest, momento, politica)?;
        let a_assinar = sha256(&atributos.to_der().map_err(der)?);
        Ok(Montador {
            certificado,
            atributos,
            conteudo: anexar,
            a_assinar,
        })
    }

    /// O que vai ao HSM. Não é o digest do documento.
    pub fn a_assinar(&self) -> &[u8; 32] {
        &self.a_assinar
    }

    /// Fecha o envelope com a assinatura do HSM e devolve o DER.
    pub fn finalizar(self, assinatura: &[u8]) -> Result<Vec<u8>, Erro> {
        let signer_info = SignerInfo {
            // V1 é o exigido com o signatário por emissor e série (RFC 5652 §5.3).
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.certificado.tbs_certificate.issuer.clone(),
                serial_number: self.certificado.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: alg_sha256(),
            signed_attrs: Some(self.atributos),
            signature_algorithm: alg_rsa(),
            signature: SignatureValue::new(assinatura).map_err(der)?,
            unsigned_attrs: None,
        };
        let econtent = match &self.conteudo {
            Some(bytes) => Some(
                Any::encode_from(&OctetString::new(bytes.as_slice()).map_err(der)?).map_err(der)?,
            ),
            None => None,
        };
        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: conjunto(vec![alg_sha256()])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: OID_DATA,
                econtent,
            },
            // Sem o certificado, o validador não tem a chave pública.
            certificates: Some(CertificateSet(conjunto(vec![
                CertificateChoices::Certificate(self.certificado),
            ])?)),
            crls: None,
            signer_infos: SignerInfos(conjunto(vec![signer_info])?),
        };
        ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).map_err(der)?,
        }
        .to_der()
        .map_err(der)
    }
}

/// Assina o documento de SHA-256 `digest` com o certificado ativo e devolve o
/// `.p7s` na [`AD_RB`]. A sessão em cache vale como numa assinatura pelo token.
pub fn assinar(
    motor: &mut Motor,
    digest: &[u8],
    anexar: Option<Vec<u8>>,
    momento: u64,
    autorizador: &dyn Autorizador,
) -> Result<Vec<u8>, motor::Erro> {
    let certificado = motor
        .estado
        .certificado()
        .cloned()
        .ok_or(motor::Erro::NaoPreparado("a carteira está vazia"))?;
    assinar_com(motor, &certificado, digest, anexar, momento, autorizador)
}

/// Como [`assinar`], com `certificado` em vez do ativo.
pub fn assinar_com(
    motor: &mut Motor,
    certificado: &Certificado,
    digest: &[u8],
    anexar: Option<Vec<u8>>,
    momento: u64,
    autorizador: &dyn Autorizador,
) -> Result<Vec<u8>, motor::Erro> {
    let envelope = |e: Erro| motor::Erro::Envelope(e.to_string());
    let der = certificado
        .base64
        .as_deref()
        .and_then(de_b64)
        .ok_or(motor::Erro::NaoPreparado(
            "a carteira não trouxe o certificado",
        ))?;
    let montador = Montador::novo(&der, digest, momento, anexar, Some(&AD_RB)).map_err(envelope)?;
    let assinatura = motor.assinar_com(
        certificado,
        Algoritmo::Sha256,
        montador.a_assinar(),
        autorizador,
    )?;
    montador.finalizar(&assinatura).map_err(envelope)
}

fn atributos(
    certificado: &Certificate,
    digest: &[u8],
    momento: u64,
    politica: Option<&Politica>,
) -> Result<SignedAttributes, Erro> {
    let hora = UtcTime::from_unix_duration(std::time::Duration::from_secs(momento)).map_err(der)?;
    let mut atributos = vec![
        atributo(OID_CONTENT_TYPE, &OID_DATA)?,
        atributo(OID_MESSAGE_DIGEST, &OctetString::new(digest).map_err(der)?)?,
        atributo(OID_SIGNING_TIME, &Time::UtcTime(hora))?,
        atributo(OID_SIGNING_CERT_V2, &signing_certificate_v2(certificado)?)?,
    ];
    if let Some(politica) = politica {
        atributos.push(atributo(
            OID_SIG_POLICY_ID,
            &signature_policy_id(politica)?,
        )?);
    }
    SignedAttributes::try_from(atributos).map_err(der)
}

fn signature_policy_id(politica: &Politica) -> Result<SignaturePolicyId, Erro> {
    Ok(SignaturePolicyId {
        sig_policy_id: politica.oid,
        sig_policy_hash: OtherHashAlgAndValue {
            // Sem parâmetros, pela Nota 3 do DOC-ICP-15.03.
            hash_algorithm: alg_sha256(),
            hash_value: OctetString::new(politica.hash).map_err(der)?,
        },
        sig_policy_qualifiers: Some(vec![SigPolicyQualifierInfo {
            sig_policy_qualifier_id: OID_SPQ_URI,
            sig_qualifier: Any::encode_from(&Ia5String::new(politica.uri).map_err(der)?)
                .map_err(der)?,
        }]),
    })
}

/// O hash do certificado e o par emissor e série: trocar o certificado do
/// envelope invalida a assinatura.
fn signing_certificate_v2(certificado: &Certificate) -> Result<SigningCertificateV2, Erro> {
    let hash = sha256(&certificado.to_der().map_err(der)?);
    Ok(SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(hash).map_err(der)?,
            issuer_serial: Some(IssuerSerial {
                issuer: vec![GeneralName::DirectoryName(
                    certificado.tbs_certificate.issuer.clone(),
                )],
                serial_number: certificado.tbs_certificate.serial_number.clone(),
            }),
        }],
    })
}

fn atributo<T: der::Tagged + der::EncodeValue>(
    oid: ObjectIdentifier,
    valor: &T,
) -> Result<Attribute, Erro> {
    let valor: AttributeValue = Any::encode_from(valor).map_err(der)?;
    Ok(Attribute {
        oid,
        values: conjunto(vec![valor])?,
    })
}

/// `SET OF` em DER: o `SetOfVec` ordena os elementos pela codificação.
fn conjunto<T: der::DerOrd>(itens: Vec<T>) -> Result<SetOfVec<T>, Erro> {
    SetOfVec::try_from(itens).map_err(der)
}

/// RFC 5754 §2: para SHA-2 os parâmetros são omitidos, não NULL.
fn alg_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: None,
    }
}

/// Aqui, ao contrário, NULL explícito (RFC 3370 §3.2).
fn alg_rsa() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_RSA,
        parameters: Some(Any::null()),
    }
}
