//! Percorre o módulo pela fronteira C, do jeito que o NSS percorre.
//!
//! Os testes unitários provam as peças; este prova a sequência inteira —
//! `C_Initialize` → slot → token → sessão → busca → atributos — chamando os
//! ponteiros que saem da `CK_FUNCTION_LIST`, e não as funções do Rust. É a
//! diferença entre "a lógica está certa" e "o hospedeiro consegue usar".
//!
//! **Tudo em um único `#[test]` de propósito.** O estado do módulo é global por
//! processo (é o que o Cryptoki manda), e `REMOTEID_HOME` é variável de
//! ambiente: dois testes em paralelo disputariam os dois. Um teste só, em
//! ordem, elimina a corrida.

use std::ffi::c_void;
use std::ptr;

use cryptoki_sys::*;
use der::Encode as _;
use remoteid_caminhos::caminho_estado;
use remoteid_estado::{Certificado, Estado};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

/// Certificado autoassinado que faz o papel do certificado da carteira.
///
/// Devolve o DER do certificado e a chave privada (em PEM PKCS#8): em modo de
/// teste a chave é gravada ao lado do `state.json`, para o `C_Sign` do módulo
/// assinar localmente sem tocar em HSM nem gastar OTP.
fn certificado_de_teste() -> (Vec<u8>, String) {
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
    let der = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(0x12CCu32),
        Validity::from_now(std::time::Duration::from_secs(86_400)).unwrap(),
        // Sintético: nunca usar CPF nem nome reais em teste.
        Name::from_str("CN=TITULAR DE TESTE:00000000000,O=ICP-Brasil,C=BR").unwrap(),
        spki,
        &assinador,
    )
    .unwrap()
    .build()
    .unwrap()
    .to_der()
    .unwrap();
    use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
    let pem = chave.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    (der, pem)
}

/// Escreve um `state.json` de mentira e aponta `REMOTEID_HOME` para ele.
/// Grava também a chave privada em `chave-assinatura.pem`, o gatilho do modo
/// de teste.
fn preparar_estado(der: &[u8], chave_pem: &str) -> std::path::PathBuf {
    use base64::Engine as _;

    let dir = std::env::temp_dir().join(format!("dtid-pkcs11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("REMOTEID_HOME", &dir);

    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let estado = Estado {
        codigo_desktop: Some("00000000-0000-0000-0000-000000000000".into()),
        certificados: vec![Certificado::do_key_name(
            "12CC6B560ECE122AC1047AA7BE71DBC3;CN=AC de Teste, O=ICP-Brasil, C=BR",
            Some(b64),
        )
        .unwrap()],
        ..Default::default()
    };
    remoteid_store_json::gravar(&estado, &caminho_estado(&dir)).unwrap();
    std::fs::write(dir.join("chave-assinatura.pem"), chave_pem).unwrap();
    dir
}

/// Lê um atributo do objeto nas duas passadas que a especificação define:
/// primeiro só o tamanho, depois o valor.
unsafe fn ler_atributo(
    lista: &CK_FUNCTION_LIST,
    sessao: CK_SESSION_HANDLE,
    objeto: CK_OBJECT_HANDLE,
    tipo: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    let get = lista.C_GetAttributeValue.unwrap();

    let mut attr = CK_ATTRIBUTE {
        type_: tipo,
        pValue: ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(
        get(sessao, objeto, &mut attr, 1),
        CKR_OK,
        "tamanho do atributo {tipo:#x}"
    );
    assert_ne!(attr.ulValueLen, CK_ULONG::MAX, "atributo {tipo:#x} ausente");

    let mut buffer = vec![0u8; attr.ulValueLen as usize];
    attr.pValue = buffer.as_mut_ptr() as *mut c_void;
    assert_eq!(
        get(sessao, objeto, &mut attr, 1),
        CKR_OK,
        "valor do atributo {tipo:#x}"
    );
    buffer.truncate(attr.ulValueLen as usize);
    buffer
}

#[test]
fn o_nss_consegue_chegar_ao_certificado_pelo_abi() {
    let (der, chave_pem) = certificado_de_teste();
    let dir = preparar_estado(&der, &chave_pem);

    unsafe {
        // --- a tabela, que é o único símbolo procurado por nome ---
        let mut p: *mut CK_FUNCTION_LIST = ptr::null_mut();
        assert_eq!(remoteid_pkcs11::C_GetFunctionList(&mut p), CKR_OK);
        let lista = &*p;

        // Antes de C_Initialize, tudo o mais tem de recusar.
        assert_eq!(
            lista.C_GetSlotList.unwrap()(CK_FALSE, ptr::null_mut(), &mut 0),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );

        assert_eq!(lista.C_Initialize.unwrap()(ptr::null_mut()), CKR_OK);
        assert_eq!(
            lista.C_Initialize.unwrap()(ptr::null_mut()),
            CKR_CRYPTOKI_ALREADY_INITIALIZED
        );

        // --- slots: duas passadas, como o NSS faz ---
        let mut n: CK_ULONG = 0;
        assert_eq!(
            lista.C_GetSlotList.unwrap()(CK_TRUE, ptr::null_mut(), &mut n),
            CKR_OK
        );
        assert_eq!(n, 1, "há certificado no estado: o token está presente");

        let mut slots = vec![0 as CK_SLOT_ID; n as usize];
        assert_eq!(
            lista.C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut n),
            CKR_OK
        );
        let slot = slots[0];

        // Buffer pequeno demais tem de dizer o tamanho, não estourar.
        let mut zero: CK_ULONG = 0;
        assert_eq!(
            lista.C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut zero),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(zero, 1);

        assert_eq!(
            lista.C_GetSlotInfo.unwrap()(slot + 99, &mut std::mem::zeroed()),
            CKR_SLOT_ID_INVALID
        );

        // --- token ---
        let mut ti: CK_TOKEN_INFO = std::mem::zeroed();
        assert_eq!(lista.C_GetTokenInfo.unwrap()(slot, &mut ti), CKR_OK);
        assert_eq!(&ti.label[..18], b"RemoteID Certisign");
        assert!(
            ti.label[18..].iter().all(|c| *c == b' '),
            "campo preenchido com espaço"
        );
        assert_eq!(ti.flags & CKF_WRITE_PROTECTED, CKF_WRITE_PROTECTED);
        // O módulo NÃO exige login: a autenticação real (PIN+OTP) é no app, no
        // C_Sign. Anunciar login exigido fazia o NSS/poppler recusar a senha em
        // loop ("Password was not accepted") sem assinar — ver
        // [[remoteid-pkcs11-c-sign]].
        assert_eq!(ti.flags & CKF_LOGIN_REQUIRED, 0, "o módulo não exige login");
        assert_eq!(
            ti.flags & CKF_USER_PIN_INITIALIZED,
            0,
            "não há PIN no nível do módulo"
        );

        // --- sessão ---
        let abrir = lista.C_OpenSession.unwrap();
        let mut sessao: CK_SESSION_HANDLE = 0;
        assert_eq!(
            abrir(slot, 0, ptr::null_mut(), None, &mut sessao),
            CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            "sem CKF_SERIAL_SESSION não há sessão legal"
        );
        assert_eq!(
            abrir(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut sessao
            ),
            CKR_TOKEN_WRITE_PROTECTED,
            "o token é só de leitura"
        );
        assert_eq!(
            abrir(slot, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut sessao),
            CKR_OK
        );
        assert_ne!(sessao, 0);

        let mut si: CK_SESSION_INFO = std::mem::zeroed();
        assert_eq!(lista.C_GetSessionInfo.unwrap()(sessao, &mut si), CKR_OK);
        assert_eq!(si.state, CKS_RO_PUBLIC_SESSION);

        // --- busca: exatamente o que o NSS pergunta ao varrer certificados ---
        let classe = CKO_CERTIFICATE;
        let mut gabarito = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &classe as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        assert_eq!(
            lista.C_FindObjectsInit.unwrap()(sessao, gabarito.as_mut_ptr(), 1),
            CKR_OK
        );
        assert_eq!(
            lista.C_FindObjectsInit.unwrap()(sessao, gabarito.as_mut_ptr(), 1),
            CKR_OPERATION_ACTIVE,
            "duas buscas na mesma sessão não podem se sobrepor"
        );

        let mut achados = [0 as CK_OBJECT_HANDLE; 8];
        let mut quantos: CK_ULONG = 0;
        assert_eq!(
            lista.C_FindObjects.unwrap()(sessao, achados.as_mut_ptr(), 8, &mut quantos),
            CKR_OK
        );
        assert_eq!(quantos, 1, "o certificado da carteira aparece na busca");
        let objeto = achados[0];

        // A segunda chamada devolve zero: é assim que o hospedeiro sabe que
        // acabou.
        assert_eq!(
            lista.C_FindObjects.unwrap()(sessao, achados.as_mut_ptr(), 8, &mut quantos),
            CKR_OK
        );
        assert_eq!(quantos, 0);
        assert_eq!(lista.C_FindObjectsFinal.unwrap()(sessao), CKR_OK);

        // --- atributos ---
        assert_eq!(
            ler_atributo(lista, sessao, objeto, CKA_VALUE),
            der,
            "CKA_VALUE é o DER do certificado, byte a byte"
        );
        assert_eq!(
            ler_atributo(lista, sessao, objeto, CKA_CLASS),
            CKO_CERTIFICATE.to_ne_bytes().to_vec()
        );
        assert_eq!(
            ler_atributo(lista, sessao, objeto, CKA_CERTIFICATE_TYPE),
            CKC_X_509.to_ne_bytes().to_vec()
        );
        assert_eq!(
            ler_atributo(lista, sessao, objeto, CKA_LABEL),
            b"TITULAR DE TESTE:00000000000".to_vec(),
            "o rótulo sai do CN, que é o que o certutil mostra"
        );
        // CKA_SERIAL_NUMBER é o DER do INTEGER, não o número em texto.
        assert_eq!(
            ler_atributo(lista, sessao, objeto, CKA_SERIAL_NUMBER),
            vec![0x02, 0x02, 0x12, 0xCC]
        );
        assert_eq!(
            ler_atributo(lista, sessao, objeto, CKA_PRIVATE),
            vec![CK_FALSE]
        );

        // Atributo que o objeto não tem: erro por atributo, e o resto continua.
        let mut misto = [
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        assert_eq!(
            lista.C_GetAttributeValue.unwrap()(sessao, objeto, misto.as_mut_ptr(), 2),
            CKR_ATTRIBUTE_TYPE_INVALID
        );
        assert_eq!(
            misto[0].ulValueLen,
            CK_ULONG::MAX,
            "o ausente vira CK_UNAVAILABLE_INFORMATION"
        );
        assert_eq!(
            misto[1].ulValueLen,
            std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            "o presente é respondido mesmo assim"
        );

        // --- assinatura ---
        // A chave privada apareceu na busca? (busca só por classe agora)
        let classe = CKO_PRIVATE_KEY;
        let mut gab = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &classe as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        assert_eq!(
            lista.C_FindObjectsInit.unwrap()(sessao, gab.as_mut_ptr(), 1),
            CKR_OK
        );
        let mut achados = [0 as CK_OBJECT_HANDLE; 4];
        let mut quantos: CK_ULONG = 0;
        assert_eq!(
            lista.C_FindObjects.unwrap()(sessao, achados.as_mut_ptr(), 4, &mut quantos),
            CKR_OK
        );
        assert_eq!(quantos, 1, "a chave privada tem de aparecer");
        let chave = achados[0];
        assert_eq!(lista.C_FindObjectsFinal.unwrap()(sessao), CKR_OK);

        // CKA_ID da chave = CKA_ID do certificado (é assim que o poppler pareia)
        assert_eq!(
            ler_atributo(lista, sessao, chave, CKA_ID),
            ler_atributo(lista, sessao, objeto, CKA_ID),
        );

        // CKA_VALUE / CKA_PRIVATE_EXPONENT na chave privada: sensível
        let mut sensivel = [CK_ATTRIBUTE {
            type_: CKA_PRIVATE_EXPONENT,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }];
        assert_eq!(
            lista.C_GetAttributeValue.unwrap()(sessao, chave, sensivel.as_mut_ptr(), 1),
            CKR_ATTRIBUTE_SENSITIVE,
            "chave privada não expõe expoente privado"
        );

        let mut mec = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        // O módulo NÃO exige login: o `C_Sign` autentica no app (PIN+OTP). O
        // `C_Login` continua existindo como no-op, para hosts que insistam em
        // chamá-lo — mas NÃO é pré-requisito do `C_SignInit`.
        let pin = b"0000";
        assert_eq!(
            lista.C_Login.unwrap()(
                sessao,
                CKU_USER,
                pin.as_ptr() as *mut _,
                pin.len() as CK_ULONG
            ),
            CKR_OK,
            "C_Login é no-op e aceita qualquer PIN"
        );
        assert_eq!(
            lista.C_Login.unwrap()(
                sessao,
                CKU_USER,
                pin.as_ptr() as *mut _,
                pin.len() as CK_ULONG
            ),
            CKR_USER_ALREADY_LOGGED_IN
        );

        // Mecanismo inválido: só RSA_PKCS.
        let mut mec_ruim = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS_PSS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert_eq!(
            lista.C_SignInit.unwrap()(sessao, &mut mec_ruim, chave),
            CKR_MECHANISM_INVALID
        );
        // Passar o certificado como chave: erro específico.
        assert_eq!(
            lista.C_SignInit.unwrap()(sessao, &mut mec, objeto),
            CKR_KEY_HANDLE_INVALID
        );
        // Sessão inexistente: o código da especificação, não um pânico
        // convertido em CKR_GENERAL_ERROR.
        assert_eq!(
            lista.C_SignInit.unwrap()(sessao + 99, &mut mec, chave),
            CKR_SESSION_HANDLE_INVALID
        );

        assert_eq!(lista.C_SignInit.unwrap()(sessao, &mut mec, chave), CKR_OK);
        assert_eq!(
            lista.C_SignInit.unwrap()(sessao, &mut mec, chave),
            CKR_OPERATION_ACTIVE,
            "duas assinaturas na mesma sessão não podem se sobrepor"
        );

        // O que o poppler manda para CKM_RSA_PKCS é o DigestInfo pronto.
        // Simulo isso aqui: DigestInfo(SHA-256, <32 bytes>).
        let mut msg = b"documento a assinar".to_vec();
        let hash: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&msg).into()
        };
        let mut digestinfo = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        digestinfo.extend_from_slice(&hash);

        // Consulta de tamanho: 256 bytes.
        let mut tam: CK_ULONG = 0;
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                ptr::null_mut(),
                &mut tam,
            ),
            CKR_OK
        );
        assert_eq!(tam, 256, "RSA-2048 sempre 256 bytes");

        // Buffer pequeno demais: BUFFER_TOO_SMALL e o tamanho volta certo.
        let mut curto = vec![0u8; 32];
        let mut tam_curto: CK_ULONG = curto.len() as CK_ULONG;
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                curto.as_mut_ptr(),
                &mut tam_curto,
            ),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(tam_curto, 256);

        // Agora a assinatura de verdade.
        let mut assinatura = vec![0u8; 256];
        let mut tam_ass: CK_ULONG = 256;
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                assinatura.as_mut_ptr(),
                &mut tam_ass,
            ),
            CKR_OK
        );
        assert_eq!(tam_ass, 256);

        // Verificação: a assinatura tem de fechar contra a chave PÚBLICA extraída
        // do certificado — não da chave privada que gravamos. É o que prova que
        // `CKA_MODULUS` e `CKA_PUBLIC_EXPONENT` batem com o SPKI e que a
        // assinatura funciona pelo caminho que o hospedeiro real vai usar.
        use der::Decode as _;
        use rsa::pkcs1::DecodeRsaPublicKey as _;
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::traits::PublicKeyParts as _;
        let cert = x509_cert::Certificate::from_der(&der).unwrap();
        let pubkey = rsa::RsaPublicKey::from_pkcs1_der(
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();
        assert_eq!(pubkey.size(), 256);
        pubkey
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &assinatura)
            .expect("assinatura tem de fechar contra a chave pública do certificado");

        // A operação foi consumida: outra C_Sign sem novo C_SignInit é erro.
        let _ = &mut msg;
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                assinatura.as_mut_ptr(),
                &mut tam_ass,
            ),
            CKR_OPERATION_NOT_INITIALIZED
        );

        // --- CKM_RSA_PKCS é passagem direta: o bloco vai como está ---
        //
        // O modo cru (issue #11): o que chega no CKM_RSA_PKCS recebe SÓ o
        // padding PKCS#1 v1.5, seja um DigestInfo(MD5) de 34 bytes (o que o
        // PJeOffice manda para autenticar), seja um hash cru de 32 bytes. Nada
        // de reconhecer DigestInfo de SHA-256 e desmontar. Verificação com
        // `new_unprefixed`: a assinatura fecha sobre os bytes enviados, e
        // NÃO como SHA-256 do bloco.
        for bloco in [
            // DigestInfo(MD5) sintético: prefixo DER real, hash de mentira.
            {
                let mut b = vec![
                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02,
                    0x05, 0x05, 0x00, 0x04, 0x10,
                ];
                b.extend_from_slice(&[0x5a; 16]);
                b
            },
            vec![0x33; 32],
            vec![0x44; 245],
        ] {
            let mut bloco = bloco;
            assert_eq!(lista.C_SignInit.unwrap()(sessao, &mut mec, chave), CKR_OK);
            let mut ass = vec![0u8; 256];
            let mut n: CK_ULONG = 256;
            assert_eq!(
                lista.C_Sign.unwrap()(
                    sessao,
                    bloco.as_mut_ptr(),
                    bloco.len() as CK_ULONG,
                    ass.as_mut_ptr(),
                    &mut n,
                ),
                CKR_OK,
                "bloco de {} bytes",
                bloco.len()
            );
            pubkey
                .verify(Pkcs1v15Sign::new_unprefixed(), &bloco, &ass)
                .expect("assinatura crua sobre o bloco inteiro");
            assert!(
                pubkey
                    .verify(Pkcs1v15Sign::new::<Sha256>(), &bloco, &ass)
                    .is_err(),
                "o módulo NÃO pode ter embrulhado o bloco em SHA-256"
            );
        }
        // Acima do teto do PKCS#1 v1.5: recusado, e o erro consome a operação.
        let mut grande = vec![0x55u8; 246];
        assert_eq!(lista.C_SignInit.unwrap()(sessao, &mut mec, chave), CKR_OK);
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                grande.as_mut_ptr(),
                grande.len() as CK_ULONG,
                assinatura.as_mut_ptr(),
                &mut tam_ass,
            ),
            CKR_DATA_LEN_RANGE
        );
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                assinatura.as_mut_ptr(),
                &mut tam_ass,
            ),
            CKR_OPERATION_NOT_INITIALIZED
        );

        // --- assinatura em FLUXO: C_SignInit → C_SignUpdate(n) → C_SignFinal ---
        //
        // É o caminho que o BouncyCastle usa, e portanto o PJeOffice: ele
        // escreve o documento num `SignatureUpdatingOutputStream` e NUNCA chama
        // `C_Sign`. Enquanto isto não existia, o `update` devolvia
        // `CKR_FUNCTION_NOT_SUPPORTED` e não dava para assinar (issue #7).

        // Sem `C_SignInit` antes, os dois são operação não iniciada — e não
        // erro de argumento.
        assert_eq!(
            lista.C_SignUpdate.unwrap()(sessao, digestinfo.as_mut_ptr(), 4),
            CKR_OPERATION_NOT_INITIALIZED
        );
        assert_eq!(
            lista.C_SignFinal.unwrap()(sessao, assinatura.as_mut_ptr(), &mut tam_ass),
            CKR_OPERATION_NOT_INITIALIZED
        );

        assert_eq!(lista.C_SignInit.unwrap()(sessao, &mut mec, chave), CKR_OK);

        // Em pedaços pequenos, como um hospedeiro que escreve um stream faz.
        for pedaco in digestinfo.chunks_mut(7) {
            let n = pedaco.len() as CK_ULONG;
            assert_eq!(
                lista.C_SignUpdate.unwrap()(sessao, pedaco.as_mut_ptr(), n),
                CKR_OK
            );
        }
        // Pedaço vazio é chamada legítima e não pode atrapalhar.
        assert_eq!(
            lista.C_SignUpdate.unwrap()(sessao, std::ptr::null_mut(), 0),
            CKR_OK
        );

        // Consulta de tamanho no `C_SignFinal` não consome a operação.
        let mut tam_consulta: CK_ULONG = 0;
        assert_eq!(
            lista.C_SignFinal.unwrap()(sessao, std::ptr::null_mut(), &mut tam_consulta),
            CKR_OK
        );
        assert_eq!(tam_consulta, 256);

        let mut ass_fluxo = vec![0u8; 256];
        let mut tam_fluxo: CK_ULONG = 256;
        assert_eq!(
            lista.C_SignFinal.unwrap()(sessao, ass_fluxo.as_mut_ptr(), &mut tam_fluxo),
            CKR_OK
        );
        assert_eq!(tam_fluxo, 256);

        // O que prova o conserto: assinar em fluxo dá o MESMO resultado que
        // assinar de um tiro só sobre os mesmos bytes.
        assert_eq!(
            ass_fluxo, assinatura,
            "C_SignFinal divergiu do C_Sign sobre o mesmo conteúdo"
        );
        pubkey
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &ass_fluxo)
            .expect("a assinatura em fluxo tem de fechar contra a chave pública");

        // Depois do `C_SignFinal` a sessão volta ao normal: um segundo é erro.
        assert_eq!(
            lista.C_SignFinal.unwrap()(sessao, ass_fluxo.as_mut_ptr(), &mut tam_fluxo),
            CKR_OPERATION_NOT_INITIALIZED
        );

        // --- cifra: C_EncryptInit → C_Encrypt, só com a chave PÚBLICA ---
        //
        // O que a issue #10 pede: `CKM_RSA_PKCS` anuncia `CKF_ENCRYPT`, que é
        // o gate do SunPKCS11 (JDK-8176837) para registrar o `Cipher` de RSA,
        // a única porta JCA para RSA cru num token. E um token que anuncia
        // cifra tem de cifrar com a pública e recusar a privada.
        let info_mec = lista.C_GetMechanismInfo.unwrap();
        let mut mi: CK_MECHANISM_INFO = std::mem::zeroed();
        assert_eq!(info_mec(slot, CKM_RSA_PKCS, &mut mi), CKR_OK);
        assert_eq!(
            mi.flags & (CKF_SIGN | CKF_ENCRYPT),
            CKF_SIGN | CKF_ENCRYPT,
            "CKM_RSA_PKCS assina E cifra"
        );
        assert_eq!(mi.flags & CKF_DECRYPT, 0, "não há como decifrar sem o HSM");
        assert_eq!(mi.ulMinKeySize, 2048);
        assert_eq!(info_mec(slot, CKM_SHA256_RSA_PKCS, &mut mi), CKR_OK);
        assert_eq!(mi.flags, CKF_SIGN, "CKM_SHA256_RSA_PKCS é só assinatura");
        assert_eq!(
            info_mec(slot, CKM_RSA_X_509, &mut mi),
            CKR_MECHANISM_INVALID,
            "mecanismo que o token não anuncia"
        );

        // A chave pública, pela busca por classe.
        let classe = CKO_PUBLIC_KEY;
        let mut gab = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &classe as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        }];
        assert_eq!(
            lista.C_FindObjectsInit.unwrap()(sessao, gab.as_mut_ptr(), 1),
            CKR_OK
        );
        let mut achados = [0 as CK_OBJECT_HANDLE; 4];
        let mut quantos: CK_ULONG = 0;
        assert_eq!(
            lista.C_FindObjects.unwrap()(sessao, achados.as_mut_ptr(), 4, &mut quantos),
            CKR_OK
        );
        assert_eq!(quantos, 1, "a chave pública tem de aparecer");
        let publica = achados[0];
        assert_eq!(lista.C_FindObjectsFinal.unwrap()(sessao), CKR_OK);
        assert_eq!(
            ler_atributo(lista, sessao, publica, CKA_ENCRYPT),
            vec![CK_TRUE],
            "o atributo acompanha o CKF_ENCRYPT do mecanismo"
        );

        let cifra_init = lista.C_EncryptInit.unwrap();
        let cifrar = lista.C_Encrypt.unwrap();
        assert_eq!(
            cifra_init(sessao + 99, &mut mec, publica),
            CKR_SESSION_HANDLE_INVALID
        );
        let mut mec_sha = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert_eq!(
            cifra_init(sessao, &mut mec_sha, publica),
            CKR_MECHANISM_INVALID,
            "só o CKM_RSA_PKCS cifra"
        );
        assert_eq!(
            cifra_init(sessao, &mut mec, chave),
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            "a chave privada não cifra: é uma chave, mas a operação é proibida"
        );
        assert_eq!(
            cifra_init(sessao, &mut mec, objeto),
            CKR_KEY_HANDLE_INVALID,
            "o certificado não é chave"
        );
        let mut tam_cifra: CK_ULONG = 0;
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                ptr::null_mut(),
                &mut tam_cifra,
            ),
            CKR_OPERATION_NOT_INITIALIZED,
            "sem C_EncryptInit antes"
        );

        assert_eq!(cifra_init(sessao, &mut mec, publica), CKR_OK);
        assert_eq!(
            cifra_init(sessao, &mut mec, publica),
            CKR_OPERATION_ACTIVE,
            "duas cifras na mesma sessão não podem se sobrepor"
        );

        // Consulta de tamanho e buffer pequeno: mesmo protocolo do C_Sign, e
        // nenhum dos dois consome a operação.
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                ptr::null_mut(),
                &mut tam_cifra,
            ),
            CKR_OK
        );
        assert_eq!(tam_cifra, 256, "o bloco cifrado tem o tamanho do módulo");
        let mut curto = vec![0u8; 32];
        let mut tam_curto: CK_ULONG = curto.len() as CK_ULONG;
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                curto.as_mut_ptr(),
                &mut tam_curto,
            ),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(tam_curto, 256);

        // Bloco maior que `k - 11`: recusado, e o erro consome a operação.
        let mut cifrado = vec![0u8; 256];
        let mut tam_cifrado: CK_ULONG = 256;
        let mut grande = vec![0xAAu8; 246];
        assert_eq!(
            cifrar(
                sessao,
                grande.as_mut_ptr(),
                grande.len() as CK_ULONG,
                cifrado.as_mut_ptr(),
                &mut tam_cifrado,
            ),
            CKR_DATA_LEN_RANGE
        );
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                cifrado.as_mut_ptr(),
                &mut tam_cifrado,
            ),
            CKR_OPERATION_NOT_INITIALIZED,
            "o erro de dados terminou a operação"
        );

        // A cifra de verdade, e a prova: a chave PRIVADA de teste decifra o que
        // a pública do certificado cifrou.
        assert_eq!(cifra_init(sessao, &mut mec, publica), CKR_OK);
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                cifrado.as_mut_ptr(),
                &mut tam_cifrado,
            ),
            CKR_OK
        );
        assert_eq!(tam_cifrado, 256);
        {
            use rsa::pkcs8::DecodePrivateKey as _;
            let privada = RsaPrivateKey::from_pkcs8_pem(&chave_pem).unwrap();
            assert_eq!(
                privada.decrypt(rsa::Pkcs1v15Encrypt, &cifrado).unwrap(),
                digestinfo,
                "a privada do certificado tem de decifrar o C_Encrypt"
            );
        }
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                cifrado.as_mut_ptr(),
                &mut tam_cifrado,
            ),
            CKR_OPERATION_NOT_INITIALIZED,
            "a cifra foi consumida"
        );

        // Cifra e assinatura são operações independentes na mesma sessão.
        assert_eq!(cifra_init(sessao, &mut mec, publica), CKR_OK);
        assert_eq!(lista.C_SignInit.unwrap()(sessao, &mut mec, chave), CKR_OK);
        assert_eq!(
            lista.C_Sign.unwrap()(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                assinatura.as_mut_ptr(),
                &mut tam_ass,
            ),
            CKR_OK
        );
        assert_eq!(
            cifrar(
                sessao,
                digestinfo.as_mut_ptr(),
                digestinfo.len() as CK_ULONG,
                cifrado.as_mut_ptr(),
                &mut tam_cifrado,
            ),
            CKR_OK,
            "assinar no meio não derruba a cifra ativa"
        );

        assert_eq!(lista.C_Logout.unwrap()(sessao), CKR_OK);
        assert_eq!(lista.C_Logout.unwrap()(sessao), CKR_USER_NOT_LOGGED_IN);

        // --- encerramento ---
        assert_eq!(lista.C_CloseSession.unwrap()(sessao), CKR_OK);
        assert_eq!(
            lista.C_CloseSession.unwrap()(sessao),
            CKR_SESSION_HANDLE_INVALID
        );
        assert_eq!(lista.C_Finalize.unwrap()(ptr::null_mut()), CKR_OK);
        assert_eq!(
            lista.C_Finalize.unwrap()(ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
