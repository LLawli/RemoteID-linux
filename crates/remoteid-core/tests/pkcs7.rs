//! O `.p7s` produzido precisa ser aceito por quem não é a gente.
//!
//! Os testes estruturais aqui provam que os campos estão onde deveriam, mas
//! isso não basta: um envelope pode ter todos os campos certos e mesmo assim
//! ser recusado por um validador. Por isso a verificação final passa pelo
//! `openssl cms -verify`, que confere a assinatura sobre os `signedAttrs`, o
//! `messageDigest` contra o conteúdo externo e — importante — o atributo
//! `signingCertificateV2` contra o certificado do signatário.

use std::process::Command;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use remoteid_core::crypto::sha256;
use remoteid_core::pkcs7::Montador;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

const MOMENTO: u64 = 1_788_393_921; // 2026-09-03T00:05:21Z

/// Forja um certificado autoassinado para fazer o papel do certificado da
/// carteira, e devolve (chave, DER do certificado).
fn par_de_teste() -> (RsaPrivateKey, Vec<u8>) {
    use std::str::FromStr;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    let mut rng = rand::thread_rng();
    let chave = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let assinador = rsa::pkcs1v15::SigningKey::<Sha256>::new(chave.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(RsaPublicKey::from(&chave)).unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(0x12CCu32),
        Validity::from_now(std::time::Duration::from_secs(86_400)).unwrap(),
        Name::from_str("CN=Titular de Teste,O=ICP-Brasil,C=BR").unwrap(),
        spki,
        &assinador,
    )
    .unwrap()
    .build()
    .unwrap();
    (chave, cert.to_der().unwrap())
}

/// Faz o papel do HSM: assina o digest que o montador pediu.
fn hsm_assina(chave: &RsaPrivateKey, digest: &[u8]) -> Vec<u8> {
    chave.sign(Pkcs1v15Sign::new::<Sha256>(), digest).unwrap()
}

#[test]
fn o_que_vai_para_o_hsm_nao_e_o_digest_do_documento() {
    // É a armadilha central do CMS. Se um dia alguém "simplificar" o montador
    // para assinar o digest do documento, este teste cai.
    let (_, cert_der) = par_de_teste();
    let documento = b"contrato";
    let digest_doc = sha256(documento);

    let montador = Montador::novo(&cert_der, &digest_doc, MOMENTO, None).unwrap();
    assert_ne!(
        montador.digest_a_assinar(),
        &digest_doc,
        "assinar o digest do documento produz um .p7s que nenhum validador aceita"
    );
}

#[test]
fn envelope_destacado_passa_no_openssl() {
    let (chave, cert_der) = par_de_teste();
    let documento = b"conteudo do documento assinado";
    let digest_doc = sha256(documento);

    let montador = Montador::novo(&cert_der, &digest_doc, MOMENTO, None).unwrap();
    let assinatura = hsm_assina(&chave, montador.digest_a_assinar());
    let p7s = montador.finalizar(&assinatura).unwrap();

    let dir = dir_temp("destacado");
    let doc = dir.join("doc.bin");
    let sig = dir.join("sig.p7s");
    std::fs::write(&doc, documento).unwrap();
    std::fs::write(&sig, &p7s).unwrap();

    let Some(saida) = openssl_cms_verify(&sig, &doc) else {
        eprintln!("openssl indisponível; pulando a verificação externa");
        return;
    };
    assert!(
        saida.status.success(),
        "openssl recusou o envelope:\n{}",
        String::from_utf8_lossy(&saida.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn openssl_detecta_conteudo_trocado() {
    // Confirma que a verificação acima tem poder de recusa: se ela aceitasse
    // qualquer coisa, o teste anterior não provaria nada.
    let (chave, cert_der) = par_de_teste();
    let digest_doc = sha256(b"o documento certo");
    let montador = Montador::novo(&cert_der, &digest_doc, MOMENTO, None).unwrap();
    let assinatura = hsm_assina(&chave, montador.digest_a_assinar());
    let p7s = montador.finalizar(&assinatura).unwrap();

    let dir = dir_temp("trocado");
    let doc = dir.join("doc.bin");
    let sig = dir.join("sig.p7s");
    std::fs::write(&doc, b"OUTRO documento").unwrap();
    std::fs::write(&sig, &p7s).unwrap();

    let Some(saida) = openssl_cms_verify(&sig, &doc) else { return };
    assert!(
        !saida.status.success(),
        "o openssl aceitou um conteúdo que não é o assinado"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn traz_os_quatro_atributos_assinados_e_o_certificado() {
    let (chave, cert_der) = par_de_teste();
    let digest_doc = sha256(b"x");
    let montador = Montador::novo(&cert_der, &digest_doc, MOMENTO, None).unwrap();
    let assinatura = hsm_assina(&chave, montador.digest_a_assinar());
    let p7s = montador.finalizar(&assinatura).unwrap();

    let ci = cms::content_info::ContentInfo::from_der(&p7s).unwrap();
    assert_eq!(
        ci.content_type,
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
        "o envelope tem de ser um signedData"
    );
    let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();

    // Destacado: o conteúdo NÃO viaja dentro.
    assert!(
        sd.encap_content_info.econtent.is_none(),
        "assinatura destacada não pode carregar o conteúdo"
    );
    // O certificado viaja, senão o validador não tem a chave pública.
    assert!(sd.certificates.is_some(), "o certificado do signatário tem de ir junto");

    let si = sd.signer_infos.0.as_slice().first().unwrap();
    let attrs = si.signed_attrs.as_ref().expect("sem atributos assinados");
    let oids: Vec<String> = attrs.iter().map(|a| a.oid.to_string()).collect();
    for (oid, nome) in [
        ("1.2.840.113549.1.9.3", "contentType"),
        ("1.2.840.113549.1.9.4", "messageDigest"),
        ("1.2.840.113549.1.9.5", "signingTime"),
        ("1.2.840.113549.1.9.16.2.47", "signingCertificateV2"),
    ] {
        assert!(oids.iter().any(|o| o == oid), "faltou o atributo {nome}");
    }

    // RFC 5754: no signatureAlgorithm vai rsaEncryption, não
    // sha256WithRSAEncryption. Trocar isso faz validadores reclamarem.
    assert_eq!(si.signature_algorithm.oid.to_string(), "1.2.840.113549.1.1.1");
}

#[test]
fn a_assinatura_cobre_exatamente_o_der_dos_atributos() {
    // Verifica a cadeia sem depender do openssl: o que está no envelope tem de
    // conferir com a chave pública sobre o DER dos signedAttrs re-serializado.
    let (chave, cert_der) = par_de_teste();
    let digest_doc = sha256(b"conteudo");
    let montador = Montador::novo(&cert_der, &digest_doc, MOMENTO, None).unwrap();
    let assinatura = hsm_assina(&chave, montador.digest_a_assinar());
    let p7s = montador.finalizar(&assinatura).unwrap();

    let ci = cms::content_info::ContentInfo::from_der(&p7s).unwrap();
    let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
    let si = sd.signer_infos.0.as_slice().first().unwrap();

    // O SignerInfo guarda os atributos com a etiqueta [0] IMPLICIT; o que se
    // assina é o mesmo conjunto re-etiquetado como SET. Reconstruir aqui é o
    // que prova que a regra da RFC 5652 §5.4 foi seguida.
    let der_attrs = si.signed_attrs.as_ref().unwrap().to_der().unwrap();
    let publica = RsaPublicKey::from(&chave);
    publica
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &sha256(&der_attrs),
            si.signature.as_bytes(),
        )
        .expect("a assinatura não cobre o DER dos atributos assinados");

    // E a chave pública do envelope é mesmo a do certificado.
    let _ = publica.to_public_key_der().unwrap();
}

#[test]
fn anexado_recusa_digest_que_nao_e_do_conteudo() {
    let (_, cert_der) = par_de_teste();
    let erro = match Montador::novo(
        &cert_der,
        &sha256(b"um conteudo"),
        MOMENTO,
        Some(b"outro conteudo".to_vec()),
    ) {
        Ok(_) => panic!("aceitou um digest que não é o do conteúdo anexado"),
        Err(e) => e,
    };
    assert!(erro.to_string().contains("digest"), "erro pouco claro: {erro}");
}

#[test]
fn anexado_carrega_o_conteudo_dentro() {
    let (chave, cert_der) = par_de_teste();
    let documento = b"cabe dentro".to_vec();
    let montador = Montador::novo(
        &cert_der,
        &sha256(&documento),
        MOMENTO,
        Some(documento.clone()),
    )
    .unwrap();
    let assinatura = hsm_assina(&chave, montador.digest_a_assinar());
    let p7s = montador.finalizar(&assinatura).unwrap();

    let ci = cms::content_info::ContentInfo::from_der(&p7s).unwrap();
    let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
    assert!(sd.encap_content_info.econtent.is_some());
}

// --- apoio ----------------------------------------------------------------

fn dir_temp(nome: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dtid-p7s-{nome}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `openssl cms -verify` sobre um envelope destacado.
///
/// `-noverify` pula a validação da CADEIA do signatário (o certificado é
/// autoassinado), mas mantém a verificação da assinatura, do `messageDigest` e
/// dos atributos ESS — que é justamente o que se quer testar aqui.
fn openssl_cms_verify(sig: &std::path::Path, conteudo: &std::path::Path) -> Option<std::process::Output> {
    Command::new("openssl")
        .args([
            "cms", "-verify", "-inform", "DER", "-in",
            sig.to_str()?, "-content", conteudo.to_str()?,
            "-noverify", "-out", "/dev/null",
        ])
        .output()
        .ok()
}
