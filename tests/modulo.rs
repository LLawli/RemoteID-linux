//! O módulo PKCS#11 pela fronteira C, do jeito que o NSS o percorre: pelos
//! ponteiros da `CK_FUNCTION_LIST`, contra o servidor falso, com um diálogo
//! falso que responde sozinho no lugar da pessoa.
//!
//! Um `#[test]` só, de propósito: o estado do módulo é global por processo,
//! como o Cryptoki manda, e o ambiente também.

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

use cryptoki_sys::*;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use remoteid::caminhos::Caminhos;
use remoteid::estado::Estado;
use remoteid::motor::Motor;
use remoteid::protocolo::Servidor;
use remoteid::protocolo::requisicao::Maquina;
use remoteid::transporte::{Http, TEMPO_LIMITE};

const TITULAR: &[u8] = include_bytes!("mock/fake-cert.der");

/// O que o diálogo falso responde. São os fatores sintéticos do servidor
/// falso.
const FATORES: &str = r#"{"senha":"teste-1234","otp":"123456"}"#;

/// Quanto o diálogo falso demora quando o teste quer uma pessoa lenta.
const DEMORA: Duration = Duration::from_secs(2);

/// O diálogo falso: anota cada pedido, espera se mandarem, e responde o que
/// estiver em `resposta`, ou desiste se o arquivo não existir.
const DIALOGO: &str = r#"#!/bin/sh
dir=$(dirname "$0")
cat >> "$dir/pedidos"
echo >> "$dir/pedidos"
[ -f "$dir/demora" ] && sleep "$(cat "$dir/demora")"
[ -f "$dir/resposta" ] || exit 1
cat "$dir/resposta"
"#;

struct Mock {
    processo: Child,
    url: String,
}

impl Mock {
    fn subir() -> Mock {
        let mut processo = Command::new(env!("CARGO_BIN_EXE_remoteid-mock"))
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut url = String::new();
        BufReader::new(processo.stdout.take().unwrap())
            .read_line(&mut url)
            .unwrap();
        Mock {
            processo,
            url: url.trim().to_string(),
        }
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
    }
}

/// Uma conta preparada no servidor falso, com o diálogo falso ao lado.
fn preparar(mock: &Mock, raiz: &Path) {
    let caminhos = Caminhos {
        raiz: raiz.to_path_buf(),
    };
    std::fs::create_dir_all(raiz).unwrap();
    std::fs::write(caminhos.chave(), include_str!("paridade/chave-teste.pem")).unwrap();
    let servidor = Servidor::falso(&mock.url);
    Motor::abrir(caminhos, servidor, Box::new(Http::novo(TEMPO_LIMITE)))
        .unwrap()
        .preparar(
            "teste@remoteid.local",
            "teste-1234",
            &Maquina {
                nome: "pc-de-teste",
                usuario_local: "teste",
                dominio_rede: "pc-de-teste",
            },
        )
        .unwrap();
}

struct Dialogo(PathBuf);

impl Dialogo {
    fn instalar(dir: &Path) -> Dialogo {
        std::fs::create_dir_all(dir).unwrap();
        let script = dir.join("dialogo");
        std::fs::write(&script, DIALOGO).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Dialogo(dir.to_path_buf())
    }

    fn responder(&self, resposta: Option<&str>, demora: Option<Duration>) {
        let _ = std::fs::remove_file(self.0.join("resposta"));
        let _ = std::fs::remove_file(self.0.join("demora"));
        if let Some(r) = resposta {
            std::fs::write(self.0.join("resposta"), r).unwrap();
        }
        if let Some(d) = demora {
            std::fs::write(self.0.join("demora"), d.as_secs().to_string()).unwrap();
        }
    }

    fn pedidos(&self) -> usize {
        std::fs::read_to_string(self.0.join("pedidos"))
            .unwrap_or_default()
            .lines()
            .count()
    }
}

fn lista() -> &'static CK_FUNCTION_LIST {
    let mut p: *mut CK_FUNCTION_LIST = ptr::null_mut();
    assert_eq!(
        unsafe { remoteid::pkcs11::C_GetFunctionList(&mut p) },
        CKR_OK
    );
    unsafe { &*p }
}

fn chave_do_titular() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(include_str!("mock/fake-key.pem")).unwrap()
}

fn mecanismo(tipo: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: tipo,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    }
}

/// Os handles que casam com `classe`.
fn buscar(
    f: &CK_FUNCTION_LIST,
    sessao: CK_SESSION_HANDLE,
    classe: CK_OBJECT_CLASS,
) -> Vec<CK_OBJECT_HANDLE> {
    let mut valor = classe;
    let mut gabarito = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: (&raw mut valor).cast(),
        ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    unsafe {
        assert_eq!(
            f.C_FindObjectsInit.unwrap()(sessao, gabarito.as_mut_ptr(), 1),
            CKR_OK
        );
        let mut handles = [0; 8];
        let mut n = 0;
        assert_eq!(
            f.C_FindObjects.unwrap()(sessao, handles.as_mut_ptr(), 8, &mut n),
            CKR_OK
        );
        assert_eq!(f.C_FindObjectsFinal.unwrap()(sessao), CKR_OK);
        handles[..n as usize].to_vec()
    }
}

fn atributo(
    f: &CK_FUNCTION_LIST,
    sessao: CK_SESSION_HANDLE,
    objeto: CK_OBJECT_HANDLE,
    tipo: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let mut attr = CK_ATTRIBUTE {
        type_: tipo,
        pValue: ptr::null_mut(),
        ulValueLen: 0,
    };
    let rv = unsafe { f.C_GetAttributeValue.unwrap()(sessao, objeto, &mut attr, 1) };
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut valor = vec![0u8; attr.ulValueLen as usize];
    attr.pValue = valor.as_mut_ptr().cast();
    match unsafe { f.C_GetAttributeValue.unwrap()(sessao, objeto, &mut attr, 1) } {
        CKR_OK => Ok(valor),
        rv => Err(rv),
    }
}

/// `C_SignInit` e `C_Sign` de uma parte, pelas duas passadas.
fn assinar(
    f: &CK_FUNCTION_LIST,
    sessao: CK_SESSION_HANDLE,
    chave: CK_OBJECT_HANDLE,
    tipo: CK_MECHANISM_TYPE,
    dados: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let mut m = mecanismo(tipo);
    let mut dados = dados.to_vec();
    unsafe {
        assert_eq!(f.C_SignInit.unwrap()(sessao, &mut m, chave), CKR_OK);
        let mut n = 0;
        let rv = f.C_Sign.unwrap()(
            sessao,
            dados.as_mut_ptr(),
            dados.len() as _,
            ptr::null_mut(),
            &mut n,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(n, 256);
        // Pedir o tamanho não gasta a operação, e um buffer pequeno também não.
        let mut pequeno = [0u8; 8];
        let mut n_pequeno = pequeno.len() as CK_ULONG;
        let rv = f.C_Sign.unwrap()(
            sessao,
            dados.as_mut_ptr(),
            dados.len() as _,
            pequeno.as_mut_ptr(),
            &mut n_pequeno,
        );
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
        let mut assinatura = vec![0u8; n as usize];
        match f.C_Sign.unwrap()(
            sessao,
            dados.as_mut_ptr(),
            dados.len() as _,
            assinatura.as_mut_ptr(),
            &mut n,
        ) {
            CKR_OK => Ok(assinatura),
            rv => Err(rv),
        }
    }
}

#[test]
fn o_modulo_assina_pelo_motor_e_pede_os_fatores_so_quando_precisa() {
    let raiz = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("modulo");
    let _ = std::fs::remove_dir_all(&raiz);
    let mock = Mock::subir();
    let conta = raiz.join("conta");
    preparar(&mock, &conta);
    let dialogo = Dialogo::instalar(&raiz.join("dialogo"));
    // SAFETY: um teste só neste binário, e o ambiente é mudado antes de o
    // módulo ter qualquer thread.
    unsafe {
        std::env::set_var("REMOTEID_HOME", &conta);
        std::env::set_var("REMOTEID_SERVIDOR", &mock.url);
        std::env::set_var("REMOTEID_DIALOGO", dialogo.0.join("dialogo"));
        // Nada no chaveiro de quem roda o teste: a senha vai pelo diálogo.
        std::env::set_var("REMOTEID_COFRE", "nenhum");
    }

    let f = lista();
    unsafe {
        assert_eq!(f.C_Initialize.unwrap()(ptr::null_mut()), CKR_OK);
        assert_eq!(
            f.C_Initialize.unwrap()(ptr::null_mut()),
            CKR_CRYPTOKI_ALREADY_INITIALIZED
        );

        let mut slots = [0; 4];
        let mut n = 4;
        assert_eq!(
            f.C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut n),
            CKR_OK
        );
        assert_eq!(n, 1);
        let slot = slots[0];
        let mut info: CK_TOKEN_INFO = std::mem::zeroed();
        assert_eq!(f.C_GetTokenInfo.unwrap()(slot, &mut info), CKR_OK);
        assert_eq!(info.flags & CKF_LOGIN_REQUIRED, 0);
        assert_ne!(info.flags & CKF_TOKEN_INITIALIZED, 0);
        assert!(info.label.starts_with(b"RemoteID Certisign "));

        let mut sessao = 0;
        let rv =
            f.C_OpenSession.unwrap()(slot, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut sessao);
        assert_eq!(rv, CKR_OK);

        // O titular primeiro, e a AC e a raiz que vieram do caIssuers.
        let [certificado, ac, ac_raiz] = buscar(f, sessao, CKO_CERTIFICATE)[..] else {
            panic!("o titular e a cadeia");
        };
        assert_eq!(
            atributo(f, sessao, ac, CKA_LABEL).unwrap(),
            b"AC TESTE DESKTOPID"
        );
        assert_eq!(
            atributo(f, sessao, ac_raiz, CKA_SUBJECT),
            atributo(f, sessao, ac_raiz, CKA_ISSUER)
        );
        let [privada] = buscar(f, sessao, CKO_PRIVATE_KEY)[..] else {
            panic!("uma chave privada só");
        };
        let [publica] = buscar(f, sessao, CKO_PUBLIC_KEY)[..] else {
            panic!("uma chave pública só");
        };
        assert_eq!(
            atributo(f, sessao, certificado, CKA_VALUE).unwrap(),
            TITULAR
        );
        assert_eq!(
            atributo(f, sessao, privada, CKA_PRIVATE_EXPONENT),
            Err(CKR_ATTRIBUTE_SENSITIVE)
        );
        assert_eq!(
            atributo(f, sessao, privada, CKA_ID),
            atributo(f, sessao, certificado, CKA_ID)
        );

        let titular = RsaPublicKey::from(&chave_do_titular());

        // A primeira assinatura abre a sessão no servidor: pede os fatores uma
        // vez.
        dialogo.responder(Some(FATORES), None);
        let documento = b"contrato de teste";
        let assinatura = assinar(f, sessao, privada, CKM_SHA256_RSA_PKCS, documento).unwrap();
        titular
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(documento),
                &assinatura,
            )
            .expect("CKM_SHA256_RSA_PKCS confere com o certificado");
        assert_eq!(dialogo.pedidos(), 1);
        let pedido = std::fs::read_to_string(dialogo.0.join("pedidos")).unwrap();
        assert!(pedido.contains("TESTE DESKTOPID"), "{pedido}");

        // Em fluxo, pelo modo cru, com o DigestInfo pronto: a sessão em cache
        // assina sem pedir nada.
        let hash = Sha256::digest(b"outro documento");
        let mut digest_info = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        digest_info.extend_from_slice(&hash);
        let mut m = mecanismo(CKM_RSA_PKCS);
        assert_eq!(f.C_SignInit.unwrap()(sessao, &mut m, privada), CKR_OK);
        for pedaco in digest_info.chunks_mut(7) {
            let rv = f.C_SignUpdate.unwrap()(sessao, pedaco.as_mut_ptr(), pedaco.len() as _);
            assert_eq!(rv, CKR_OK);
        }
        let mut assinatura = vec![0u8; 256];
        let mut n = 256;
        assert_eq!(
            f.C_SignFinal.unwrap()(sessao, assinatura.as_mut_ptr(), &mut n),
            CKR_OK
        );
        titular
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &assinatura)
            .expect("o DigestInfo cru confere com o certificado");
        assert_eq!(dialogo.pedidos(), 1);

        // Sessão vencida e a pessoa fecha o diálogo: cancelado, e a operação
        // acabou.
        ureq::post(format!("{}/_mock/expirar", mock.url))
            .send_empty()
            .unwrap();
        dialogo.responder(None, None);
        assert_eq!(
            assinar(f, sessao, privada, CKM_SHA256_RSA_PKCS, b"x"),
            Err(CKR_FUNCTION_CANCELED)
        );
        assert_eq!(dialogo.pedidos(), 2);
        let mut n = 256;
        assert_eq!(
            f.C_SignFinal.unwrap()(sessao, assinatura.as_mut_ptr(), &mut n),
            CKR_OPERATION_NOT_INITIALIZED
        );

        // Enquanto a pessoa digita, o mesmo aplicativo continua usando o
        // token: a assinatura não segura a trava do módulo.
        dialogo.responder(Some(FATORES), Some(DEMORA));
        let enquanto = std::thread::spawn(move || {
            let f = lista();
            assinar(f, sessao, privada, CKM_SHA256_RSA_PKCS, b"devagar")
        });
        while dialogo.pedidos() < 3 {
            std::thread::sleep(Duration::from_millis(20));
        }
        let comeco = Instant::now();
        let mut outra = 0;
        let rv =
            f.C_OpenSession.unwrap()(slot, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut outra);
        assert_eq!(rv, CKR_OK);
        assert_eq!(
            buscar(f, outra, CKO_CERTIFICATE),
            [certificado, ac, ac_raiz]
        );
        assert_eq!(f.C_GetTokenInfo.unwrap()(slot, &mut info), CKR_OK);
        assert!(comeco.elapsed() < DEMORA / 4, "{:?}", comeco.elapsed());
        assert!(
            !enquanto.is_finished(),
            "a assinatura ainda espera a pessoa"
        );
        let assinatura = enquanto.join().unwrap().unwrap();
        titular
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(b"devagar"),
                &assinatura,
            )
            .unwrap();

        // Cifra com a pública, para o Cipher do SunPKCS11.
        let mut m = mecanismo(CKM_RSA_PKCS);
        assert_eq!(
            f.C_EncryptInit.unwrap()(sessao, &mut m, privada),
            CKR_KEY_FUNCTION_NOT_PERMITTED
        );
        assert_eq!(f.C_EncryptInit.unwrap()(sessao, &mut m, publica), CKR_OK);
        let mut claro = b"segredo".to_vec();
        let mut cifrado = vec![0u8; 256];
        let mut n = 256;
        let rv = f.C_Encrypt.unwrap()(
            sessao,
            claro.as_mut_ptr(),
            claro.len() as _,
            cifrado.as_mut_ptr(),
            &mut n,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(
            chave_do_titular()
                .decrypt(Pkcs1v15Encrypt, &cifrado)
                .unwrap(),
            claro
        );

        // A conexão do navegador fica aberta: o módulo acompanha o estado.
        let estado = conta.join("estado.json");
        let mut slot_info: CK_SLOT_INFO = std::mem::zeroed();
        let mut sessao_info: CK_SESSION_INFO = std::mem::zeroed();
        // Gravar sem trocar o certificado, como cada assinatura faz, não mexe
        // nas sessões.
        Estado::alterar(&estado, |e| e.sessoes.clear()).unwrap();
        assert_eq!(f.C_GetSlotInfo.unwrap()(slot, &mut slot_info), CKR_OK);
        assert_ne!(slot_info.flags & CKF_REMOVABLE_DEVICE, 0);
        assert_eq!(
            f.C_GetSessionInfo.unwrap()(sessao, &mut sessao_info),
            CKR_OK
        );
        // Sair da conta é tirar o cartão: a sessão acaba e o token esvazia.
        let carteira = Estado::carregar(&estado).unwrap().certificados;
        Estado::alterar(&estado, |e| e.certificados.clear()).unwrap();
        assert_eq!(f.C_GetSlotInfo.unwrap()(slot, &mut slot_info), CKR_OK);
        assert_eq!(
            f.C_GetSessionInfo.unwrap()(sessao, &mut sessao_info),
            CKR_SESSION_HANDLE_INVALID
        );
        assert_eq!(f.C_GetTokenInfo.unwrap()(slot, &mut info), CKR_OK);
        assert_eq!(info.flags & CKF_TOKEN_INITIALIZED, 0);
        // Entrar de novo traz o token, numa sessão nova.
        Estado::alterar(&estado, |e| e.certificados = carteira).unwrap();
        assert_eq!(f.C_GetTokenInfo.unwrap()(slot, &mut info), CKR_OK);
        assert_ne!(info.flags & CKF_TOKEN_INITIALIZED, 0);
        let mut de_novo = 0;
        let rv = f.C_OpenSession.unwrap()(
            slot,
            CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut de_novo,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(buscar(f, de_novo, CKO_CERTIFICATE).len(), 3);

        assert_eq!(f.C_Finalize.unwrap()(ptr::null_mut()), CKR_OK);

        // Sem conta, o token existe, não inicializado e sem objetos: um slot
        // sem token deixa em laço quem usa o p11-kit (ver C_GetTokenInfo).
        std::env::set_var("REMOTEID_HOME", raiz.join("sem-conta"));
        assert_eq!(f.C_Initialize.unwrap()(ptr::null_mut()), CKR_OK);
        let mut n = 4;
        let rv = f.C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut n);
        assert_eq!(rv, CKR_OK);
        assert_eq!(n, 1);
        assert_eq!(f.C_GetTokenInfo.unwrap()(slot, &mut info), CKR_OK);
        assert_eq!(info.flags & CKF_TOKEN_INITIALIZED, 0);
        let mut vazia = 0;
        let rv =
            f.C_OpenSession.unwrap()(slot, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut vazia);
        assert_eq!(rv, CKR_OK);
        assert!(buscar(f, vazia, CKO_CERTIFICATE).is_empty());
        assert_eq!(f.C_Finalize.unwrap()(ptr::null_mut()), CKR_OK);
    }
    assert!(!raiz.join("sem-conta").exists(), "listar não cria nada");
}
