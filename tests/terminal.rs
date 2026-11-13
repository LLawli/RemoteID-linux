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

/// O que a janela faz, pela linha de comando.
#[test]
fn estado_usar_reautorizar_e_sair_sem_a_janela() {
    let mock = Mock::subir();
    let conta = Conta::entrar(&mock, "conta");
    let estado = |conta: &Conta| -> serde_json::Value {
        let saida = conta.rodar(&["estado", "--json"], b"");
        assert!(saida.status.success());
        serde_json::from_slice(&saida.stdout).unwrap()
    };
    let e = estado(&conta);
    assert_eq!(e["conta"]["email"], "teste@remoteid.local");
    let serie = e["certificados"][0]["serie"].as_str().unwrap().to_string();
    let texto = conta.rodar(&["estado"], b"");
    assert!(String::from_utf8_lossy(&texto.stdout).contains(&serie));

    assert!(conta.rodar(&["usar", &serie], b"").status.success());
    assert!(!conta.rodar(&["usar", "outro"], b"").status.success());
    assert!(conta.rodar(&["atualizar"], b"").status.success());

    assert!(
        conta
            .rodar(&["assinar", "--cru"], DOCUMENTO)
            .status
            .success()
    );
    assert_eq!(estado(&conta)["certificados"][0]["sessao"]["aberta"], true);
    assert!(conta.rodar(&["reautorizar"], b"").status.success());
    assert_eq!(estado(&conta)["certificados"][0]["sessao"]["aberta"], false);
    let saida = conta.rodar(&["assinar", "--cru", "--certificado", &serie], DOCUMENTO);
    assert!(saida.status.success());
    assert_eq!(conta.pedidos(), 2);

    assert!(conta.rodar(&["sair"], b"").status.success());
    assert_eq!(estado(&conta)["conta"], serde_json::Value::Null);
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

#[test]
fn o_diagnostico_empacota_registros_e_ambiente_sem_segredo() {
    let mock = Mock::subir();
    let conta = Conta::entrar(&mock, "diagnostico");
    assert!(conta.rodar(&["harness"], b"").status.success());
    assert!(conta.rodar(&["assinar"], DOCUMENTO).status.success());
    let saida = conta.rodar(&["diagnostico"], b"");
    assert!(
        saida.status.success(),
        "{}",
        String::from_utf8_lossy(&saida.stderr)
    );

    let mut pacote = tar::Archive::new(flate2::read::GzDecoder::new(&saida.stdout[..]));
    let mut conteudo = std::collections::BTreeMap::new();
    for entrada in pacote.entries().unwrap() {
        let mut entrada = entrada.unwrap();
        let nome = entrada.path().unwrap().to_string_lossy().into_owned();
        let mut texto = String::new();
        std::io::Read::read_to_string(&mut entrada, &mut texto).unwrap();
        conteudo.insert(nome, texto);
    }
    let nomes: Vec<&str> = conteudo.keys().map(String::as_str).collect();
    // O ambiente, um JSONL por comando (entrar, harness, assinar) e o
    // relatório do harness.
    assert_eq!(nomes.len(), 5, "{nomes:?}");
    assert!(nomes.iter().all(|n| n.starts_with("remoteid-diagnostico/")));
    let ambiente: serde_json::Value =
        serde_json::from_str(&conteudo["remoteid-diagnostico/ambiente.json"]).unwrap();
    assert_eq!(ambiente["versao"], env!("CARGO_PKG_VERSION"));
    assert_eq!(ambiente["arquivos"].as_array().unwrap().len(), 4);
    let processos: Vec<String> = conteudo
        .iter()
        .filter(|(n, _)| n.ends_with(".jsonl"))
        .map(|(_, t)| {
            let inicio: serde_json::Value =
                serde_json::from_str(t.lines().next().unwrap()).unwrap();
            inicio["processo"].as_str().unwrap().to_string()
        })
        .collect();
    for comando in ["terminal entrar", "terminal harness", "terminal assinar"] {
        assert!(processos.iter().any(|p| p == comando), "{processos:?}");
    }
    let tudo: String = conteudo.values().map(String::as_str).collect();
    for segredo in [
        "teste-1234",           // senha
        "\"123456\"",           // OTP
        "teste@remoteid.local", // e-mail
        "\"TESTE DESKTOPID\"",  // nome do titular
        "16C3F7EFA6CCE55817FA", // serial
        "contrato de teste",    // o documento
    ] {
        assert!(!tudo.contains(segredo), "{segredo} vazou");
    }
}
