//! O `remoteid` pela linha de comando, contra o servidor falso: o documento
//! entra pelo stdin e a assinatura sai pelo stdout. O processo roda sem
//! terminal de controle (`setsid`), então os fatores vêm do diálogo falso,
//! como num script.

mod comum;

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use comum::Mock;

const DOCUMENTO: &[u8] = b"contrato de teste";

/// Responde os fatores sintéticos do servidor falso e anota cada pedido.
const DIALOGO: &str = r#"#!/bin/sh
cat >> "$(dirname "$0")/pedidos"
echo '{"senha":"teste-1234","otp":"123456"}'
"#;

struct Conta {
    raiz: PathBuf,
    url: String,
}

impl Conta {
    /// Entra no servidor falso pelo `remoteid entrar`, sem chaveiro e sem PIN
    /// local: a senha é pedida a cada sessão, junto com o OTP.
    fn entrar(mock: &Mock, nome: &str) -> Conta {
        let raiz = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("terminal-{nome}"));
        let _ = std::fs::remove_dir_all(&raiz);
        std::fs::create_dir_all(&raiz).unwrap();
        std::fs::write(
            raiz.join("chave-instalacao.pem"),
            include_str!("paridade/chave-teste.pem"),
        )
        .unwrap();
        let dialogo = raiz.join("dialogo");
        std::fs::write(&dialogo, DIALOGO).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dialogo, std::fs::Permissions::from_mode(0o755)).unwrap();
        let conta = Conta {
            raiz,
            url: mock.url.clone(),
        };
        let saida = conta.rodar(&["entrar", "teste@remoteid.local"], b"teste-1234\n");
        assert!(
            saida.status.success(),
            "{}",
            String::from_utf8_lossy(&saida.stderr)
        );
        conta
    }

    fn rodar(&self, args: &[&str], entrada: &[u8]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_remoteid"));
        cmd.args(args)
            .env("REMOTEID_HOME", &self.raiz)
            .env("REMOTEID_SERVIDOR", &self.url)
            .env("REMOTEID_DIALOGO", self.raiz.join("dialogo"))
            .env("REMOTEID_COFRE", "nenhum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: setsid só tira o filho do terminal de quem roda o teste, e
        // não toca em memória.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut filho = cmd.spawn().unwrap();
        filho.stdin.take().unwrap().write_all(entrada).unwrap();
        filho.wait_with_output().unwrap()
    }

    fn pedidos(&self) -> usize {
        std::fs::read_to_string(self.raiz.join("pedidos"))
            .map(|t| t.matches('{').count())
            .unwrap_or(0)
    }
}

fn openssl_aceita(dir: &Path, p7s: &[u8]) -> bool {
    std::fs::write(dir.join("a.p7s"), p7s).unwrap();
    std::fs::write(dir.join("documento"), DOCUMENTO).unwrap();
    let mock = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mock");
    Command::new("openssl")
        .args([
            "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any",
        ])
        .arg("-in")
        .arg(dir.join("a.p7s"))
        .arg("-content")
        .arg(dir.join("documento"))
        .arg("-CAfile")
        .arg(format!("{mock}/fake-ac-raiz.pem"))
        .arg("-certfile")
        .arg(format!("{mock}/fake-ac.pem"))
        .arg("-out")
        .arg("/dev/null")
        .output()
        .expect("openssl no PATH")
        .status
        .success()
}

#[test]
fn assinar_le_o_documento_do_stdin_e_escreve_o_p7s_no_stdout() {
    let mock = Mock::subir();
    let conta = Conta::entrar(&mock, "p7s");
    let saida = conta.rodar(&["assinar"], DOCUMENTO);
    assert!(
        saida.status.success(),
        "{}",
        String::from_utf8_lossy(&saida.stderr)
    );
    assert!(openssl_aceita(&conta.raiz, &saida.stdout));
    assert_eq!(conta.pedidos(), 1);

    // A segunda usa a sessão em cache: não pergunta nada.
    let saida = conta.rodar(&["assinar"], DOCUMENTO);
    assert!(saida.status.success());
    assert_eq!(conta.pedidos(), 1);
}

#[test]
fn assinar_cru_devolve_a_assinatura_rsa_do_sha256() {
    let mock = Mock::subir();
    let conta = Conta::entrar(&mock, "cru");
    let saida = conta.rodar(&["assinar", "--cru"], DOCUMENTO);
    assert!(
        saida.status.success(),
        "{}",
        String::from_utf8_lossy(&saida.stderr)
    );
    let titular = RsaPrivateKey::from_pkcs8_pem(include_str!("mock/fake-key.pem")).unwrap();
    RsaPublicKey::from(&titular)
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(DOCUMENTO),
            &saida.stdout,
        )
        .expect("a assinatura crua tem de conferir com o certificado");

    // O mesmo digest, dado pronto, assina o mesmo: PKCS#1 v1.5 é determinístico.
    let hex: String = Sha256::digest(DOCUMENTO)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pelo_hash = conta.rodar(&["assinar", "--cru", "--hash", &hex], b"");
    assert_eq!(pelo_hash.stdout, saida.stdout);
}

#[test]
fn opcao_errada_nao_vai_a_rede_nem_escreve_nada() {
    let mock = Mock::subir();
    let conta = Conta::entrar(&mock, "opcao");
    let saida = conta.rodar(&["assinar", "--anexar", "--cru"], DOCUMENTO);
    assert!(!saida.status.success());
    assert!(saida.stdout.is_empty());
    assert!(String::from_utf8_lossy(&saida.stderr).contains("uso:"));
    assert_eq!(conta.pedidos(), 0);
}

#[test]
fn o_harness_pelo_terminal_grava_o_relatorio() {
    let mock = Mock::subir();
    let conta = Conta::entrar(&mock, "harness");
    let saida = conta.rodar(&["harness"], b"");
    let texto = String::from_utf8_lossy(&saida.stdout);
    assert!(saida.status.success(), "{texto}");
    assert!(texto.contains("[ok] p7s"), "{texto}");
    let relatorio = std::fs::read_dir(conta.raiz.join("diagnostico"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("harness-"))
        .count();
    assert_eq!(relatorio, 1);
}
