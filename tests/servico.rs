//! O `remoteid servir` contra o servidor falso: a API em JSON por linha, pelo
//! stdin e stdout e pelo socket Unix, com os fatores pedidos a quem chama.

mod comum;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use comum::Mock;

const DOCUMENTO: &[u8] = b"contrato de teste";

fn raiz(nome: &str) -> PathBuf {
    let raiz = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("servico-{nome}"));
    let _ = std::fs::remove_dir_all(&raiz);
    std::fs::create_dir_all(&raiz).unwrap();
    std::fs::write(
        raiz.join("chave-instalacao.pem"),
        include_str!("paridade/chave-teste.pem"),
    )
    .unwrap();
    raiz
}

fn comando(raiz: &PathBuf, mock: &Mock) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_remoteid"));
    cmd.env("REMOTEID_HOME", raiz)
        .env("REMOTEID_SERVIDOR", &mock.url)
        // Nenhum diálogo: os fatores só podem vir pelo canal.
        .env("REMOTEID_DIALOGO", "/nao/existe")
        .env("REMOTEID_COFRE", "nenhum");
    cmd
}

struct Servico {
    filho: Child,
    entrada: ChildStdin,
    saida: BufReader<ChildStdout>,
}

impl Servico {
    fn subir(raiz: &PathBuf, mock: &Mock) -> Servico {
        let mut filho = comando(raiz, mock)
            .arg("servir")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Servico {
            entrada: filho.stdin.take().unwrap(),
            saida: BufReader::new(filho.stdout.take().unwrap()),
            filho,
        }
    }

    fn enviar(&mut self, linha: &str) {
        writeln!(self.entrada, "{linha}").unwrap();
    }

    fn receber(&mut self) -> Value {
        let mut linha = String::new();
        self.saida.read_line(&mut linha).unwrap();
        serde_json::from_str(&linha).unwrap_or_else(|_| panic!("não é JSON: {linha:?}"))
    }

    fn pedir(&mut self, pedido: Value) -> Value {
        self.enviar(&pedido.to_string());
        self.receber()
    }
}

impl Drop for Servico {
    fn drop(&mut self) {
        let _ = self.filho.kill();
        let _ = self.filho.wait();
    }
}

#[test]
fn a_api_faz_tudo_o_que_a_janela_faz() {
    let mock = Mock::subir();
    let raiz = raiz("ponta-a-ponta");
    let mut s = Servico::subir(&raiz, &mock);

    // Sem chaveiro, o PIN local cifra a senha.
    let r = s.pedir(
        json!({"id": 1, "op": "entrar", "email": "teste@remoteid.local",
                           "senha": "teste-1234", "pin": "1234"}),
    );
    assert_eq!(r["ok"], json!({"chaveiro": false, "pin": true}), "{r}");

    let r = s.pedir(json!({"id": 2, "op": "estado"}));
    let estado = &r["ok"];
    assert_eq!(estado["preparado"], true);
    assert_eq!(estado["conta"]["email"], "teste@remoteid.local");
    let certificados = estado["certificados"].as_array().unwrap();
    assert_eq!(certificados.len(), 1);
    assert_eq!(certificados[0]["ativo"], true);
    assert_eq!(certificados[0]["sessao"]["aberta"], false);
    let serie = certificados[0]["serie"].as_str().unwrap().to_string();

    // A primeira assinatura pede o PIN local e o OTP; um OTP errado volta com
    // a recusa e a senha guardada, que quem chama mantém omitindo a senha.
    s.enviar(
        &json!({"id": "a", "op": "assinar", "documento": STANDARD.encode(DOCUMENTO)}).to_string(),
    );
    let p = s.receber();
    assert_eq!(p["id"], "a");
    assert_eq!(p["pedir"]["pedir_pin"], true, "{p}");
    assert_eq!(p["pedir"]["pedir_senha"], false);
    s.enviar(r#"{"id":"a","fatores":{"pin":"1234","otp":"999999"}}"#);
    let p = s.receber();
    assert_eq!(p["pedir"]["pedir_senha"], true, "{p}");
    assert_eq!(p["pedir"]["senha_guardada"], true);
    assert!(p["pedir"]["recusa"].is_string());
    assert!(!p.to_string().contains("teste-1234"), "a senha saiu: {p}");
    s.enviar(r#"{"id":"a","fatores":{"otp":"123456"}}"#);
    let r = s.receber();
    let p7s = STANDARD
        .decode(r["ok"]["assinatura"].as_str().expect("assinatura"))
        .unwrap();
    assert_eq!(p7s[0], 0x30, "um .p7s é uma SEQUENCE DER");

    // A sessão em cache assina sem perguntar nada, pela série.
    let hash = "ab".repeat(32);
    let r = s.pedir(
        json!({"id": 3, "op": "assinar", "formato": "cru", "hash": hash,
                           "certificado": serie}),
    );
    let cru = STANDARD
        .decode(r["ok"]["assinatura"].as_str().unwrap())
        .unwrap();
    assert_eq!(cru.len(), 256, "{r}");

    // Reautorizar fecha a sessão; um pedido de outro id no meio da pergunta
    // é recusado, e cancelar desiste da assinatura.
    assert_eq!(
        s.pedir(json!({"id": 4, "op": "reautorizar"}))["ok"],
        Value::Null
    );
    s.enviar(&json!({"id": 5, "op": "assinar", "hash": hash}).to_string());
    assert!(s.receber()["pedir"].is_object());
    let r = s.pedir(json!({"id": 6, "op": "estado"}));
    assert_eq!(r["erro"]["tipo"], "ocupado", "{r}");
    let r = s.pedir(json!({"id": 5, "cancelar": true}));
    assert_eq!(r["erro"]["tipo"], "cancelado", "{r}");

    let r = s.pedir(json!({"id": 7, "op": "usar", "certificado": serie}));
    assert_eq!(r["ok"]["certificados"][0]["ativo"], true, "{r}");
    let r = s.pedir(json!({"id": 8, "op": "usar", "certificado": "outro"}));
    assert!(
        r["erro"]["tipo"]
            .as_str()
            .unwrap()
            .starts_with("nao_preparado")
    );
    let r = s.pedir(json!({"id": 9, "op": "atualizar"}));
    assert!(r["ok"]["celular_pareado"].is_boolean(), "{r}");

    // Pedidos malformados não derrubam o serviço.
    s.enviar("isto não é JSON");
    assert_eq!(s.receber()["erro"]["tipo"], "pedido_invalido");
    let r = s.pedir(json!({"id": 10, "op": "voar"}));
    assert_eq!(r["erro"]["tipo"], "pedido_invalido");
    let r = s.pedir(json!({"id": 11, "op": "assinar", "formato": "anexado", "hash": hash}));
    assert_eq!(r["erro"]["tipo"], "pedido_invalido");
    let r = s.pedir(json!({"id": 12, "op": "entrar", "email": "x", "senha": "y", "pin": "12"}));
    assert_eq!(r["erro"]["tipo"], "pedido_invalido");

    assert_eq!(s.pedir(json!({"id": 13, "op": "sair"}))["ok"], Value::Null);
    let r = s.pedir(json!({"id": 14, "op": "estado"}));
    assert_eq!(r["ok"]["conta"], Value::Null);
    assert_eq!(r["ok"]["preparado"], false);
    drop(s);

    // Nada do que entrou pelo canal foi para o diagnóstico.
    let mut tudo = String::new();
    for arquivo in std::fs::read_dir(raiz.join("diagnostico")).unwrap() {
        tudo += &std::fs::read_to_string(arquivo.unwrap().path()).unwrap();
    }
    assert!(
        tudo.contains("servir"),
        "o diagnóstico não registrou o serviço"
    );
    for segredo in [
        "teste-1234",
        "\"1234\"",
        "\"123456\"",
        "999999",
        "teste@remoteid.local",
        "contrato de teste",
    ] {
        assert!(!tudo.contains(segredo), "{segredo} vazou");
    }
}

#[test]
fn o_socket_e_so_do_dono_e_atende_cada_conexao() {
    let mock = Mock::subir();
    let raiz = raiz("socket");
    let caminho = raiz.join("remoteid.sock");
    // Um socket velho no caminho é trocado.
    drop(std::os::unix::net::UnixListener::bind(&caminho).unwrap());
    let mut filho = comando(&raiz, &mock)
        .args(["servir", "--socket"])
        .arg(&caminho)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let inicio = Instant::now();
    let conexao = loop {
        if let Ok(c) = UnixStream::connect(&caminho) {
            break c;
        }
        assert!(
            inicio.elapsed() < Duration::from_secs(10),
            "o socket não abriu"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let modo = std::fs::metadata(&caminho).unwrap().permissions().mode();
    assert_eq!(modo & 0o777, 0o600, "{modo:o}");

    let pedir = |conexao: &UnixStream, pedido: Value| {
        writeln!(&*conexao, "{pedido}").unwrap();
        let mut linha = String::new();
        BufReader::new(conexao).read_line(&mut linha).unwrap();
        serde_json::from_str::<Value>(&linha).unwrap()
    };
    let r = pedir(&conexao, json!({"id": 1, "op": "estado"}));
    assert_eq!(r["ok"]["preparado"], false, "{r}");
    let outra = UnixStream::connect(&caminho).unwrap();
    let r = pedir(&outra, json!({"id": 1, "op": "reautorizar"}));
    assert!(r["erro"].is_object(), "{r}");

    let _ = filho.kill();
    let _ = filho.wait();
}

#[test]
fn o_socket_nao_apaga_um_arquivo_comum() {
    let mock = Mock::subir();
    let raiz = raiz("socket-arquivo");
    let caminho = raiz.join("importante");
    std::fs::write(&caminho, "dados").unwrap();
    let saida = comando(&raiz, &mock)
        .args(["servir", "--socket"])
        .arg(&caminho)
        .output()
        .unwrap();
    assert!(!saida.status.success());
    assert_eq!(std::fs::read_to_string(&caminho).unwrap(), "dados");
}
