//! O `sigPolicyId` da AD-RB no `.p7s`, conferido contra o arquivo da política
//! publicado pelo ITI (`tests/icp-brasil/PA_AD_RB_v2_4.der`, baixado de
//! politicas.icpbrasil.gov.br em 2026-10-31; o SHA-256 dele é o da LPA).
//!
//! As estruturas da RFC 5126 são declaradas de novo aqui, de propósito: um
//! erro no `src/cades.rs` não pode se repetir no teste que o confere.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Any, Ia5String, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Reader, Sequence, SliceReader};
use x509_cert::spki::AlgorithmIdentifierOwned;

use remoteid::cades::{AD_RB, Montador};
use remoteid::cripto::sha256;

const PA: &[u8] = include_bytes!("icp-brasil/PA_AD_RB_v2_4.der");
const CERTIFICADO: &[u8] = include_bytes!("mock/fake-cert.der");

const SIG_POLICY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");
const SPURI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.5.1");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `SignaturePolicy`, RFC 3125: o arquivo da política.
#[derive(Sequence)]
struct SignaturePolicy {
    sign_policy_hash_alg: Any,
    sign_policy_info: Any,
    sign_policy_hash: OctetString,
}

#[derive(Sequence)]
struct OtherHashAlgAndValue {
    hash_algorithm: AlgorithmIdentifierOwned,
    hash_value: OctetString,
}

#[derive(Sequence)]
struct Qualificador {
    id: ObjectIdentifier,
    valor: Any,
}

#[derive(Sequence)]
struct SignaturePolicyId {
    sig_policy_id: ObjectIdentifier,
    sig_policy_hash: OtherHashAlgAndValue,
    sig_policy_qualifiers: Option<Vec<Qualificador>>,
}

fn politica() -> SignaturePolicy {
    SignaturePolicy::from_der(PA).unwrap()
}

#[test]
fn o_hash_e_o_interno_da_politica_e_confere_com_o_conteudo_dela() {
    let pa = politica();
    // A Nota 2 do DOC-ICP-15.03: o hash que vai na assinatura é o que está
    // dentro da política, e ele é o SHA-256 do algoritmo seguido da
    // informação da política.
    assert_eq!(pa.sign_policy_hash.as_bytes(), AD_RB.hash);
    let mut coberto = pa.sign_policy_hash_alg.to_der().unwrap();
    coberto.extend(pa.sign_policy_info.to_der().unwrap());
    assert_eq!(sha256(&coberto), AD_RB.hash);
    // E não o do arquivo inteiro, que é o da LPA.
    assert_ne!(sha256(PA), AD_RB.hash);

    let mut info = SliceReader::new(pa.sign_policy_info.value()).unwrap();
    let oid: ObjectIdentifier = info.decode().unwrap();
    assert_eq!(oid, AD_RB.oid);
    assert!(AD_RB.uri.ends_with("/PA_AD_RB_v2_4.der"));
}

/// Os atributos assinados do primeiro signatário.
fn atributos(p7s: &[u8]) -> Vec<(ObjectIdentifier, Any)> {
    let info = ContentInfo::from_der(p7s).unwrap();
    let dados: SignedData = info.content.decode_as().unwrap();
    let signatario = dados.signer_infos.0.as_slice()[0].clone();
    signatario
        .signed_attrs
        .unwrap()
        .iter()
        .map(|a| (a.oid, a.values.as_slice()[0].clone()))
        .collect()
}

fn p7s(politica: bool) -> Vec<u8> {
    let politica = politica.then_some(&AD_RB);
    Montador::novo(
        CERTIFICADO,
        &sha256(b"contrato"),
        1_800_000_000,
        None,
        politica,
    )
    .unwrap()
    .finalizar(&[7; 256])
    .unwrap()
}

#[test]
fn o_p7s_cita_a_ad_rb_com_o_hash_e_um_unico_spuri() {
    let atributos = atributos(&p7s(true));
    assert_eq!(atributos.len(), 5);
    let (_, valor) = atributos
        .iter()
        .find(|(oid, _)| *oid == SIG_POLICY_ID)
        .expect("sem sigPolicyId");
    let id: SignaturePolicyId = valor.decode_as().unwrap();
    assert_eq!(id.sig_policy_id, AD_RB.oid);
    assert_eq!(id.sig_policy_hash.hash_algorithm.oid, SHA256);
    // Nota 3: sem o campo parameters.
    assert!(id.sig_policy_hash.hash_algorithm.parameters.is_none());
    assert_eq!(
        id.sig_policy_hash.hash_value.as_bytes(),
        politica().sign_policy_hash.as_bytes()
    );
    // Nota 1: um único qualificador, do tipo spuri, com a URL da política.
    let qualificadores = id.sig_policy_qualifiers.unwrap();
    assert_eq!(qualificadores.len(), 1);
    assert_eq!(qualificadores[0].id, SPURI);
    let uri: Ia5String = qualificadores[0].valor.decode_as().unwrap();
    assert_eq!(uri.as_str(), AD_RB.uri);
}

#[test]
fn sem_politica_o_envelope_e_o_do_antigo() {
    let atributos = atributos(&p7s(false));
    assert_eq!(atributos.len(), 4);
    assert!(atributos.iter().all(|(oid, _)| *oid != SIG_POLICY_ID));
}

#[test]
fn a_politica_entra_no_que_vai_ao_hsm() {
    let digest = sha256(b"contrato");
    let com = Montador::novo(CERTIFICADO, &digest, 1_800_000_000, None, Some(&AD_RB)).unwrap();
    let sem = Montador::novo(CERTIFICADO, &digest, 1_800_000_000, None, None).unwrap();
    assert_ne!(com.a_assinar(), sem.a_assinar());
}
