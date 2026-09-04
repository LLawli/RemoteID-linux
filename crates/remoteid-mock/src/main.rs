//! Servidor RemoteID **falso** para teste local, ponta a ponta.
//!
//! Sobe um HTTP/1.1 mínimo (sem framework, como o servidor enlatado dos testes
//! de integração) que responde aos 6 endpoints do fluxo `preparar` + `assinar`
//! com um **certificado e uma chave falsos** (fixtures embutidas), aceitando
//! credenciais fixas. Serve para exercitar TODO o fluxo do app (login →
//! registro → carteira → tokensessao → requestHash) sem tocar na produção da
//! Certisign e sem gastar OTP de conta real.
//!
//! Nada aqui é secreto: a chave é sintética, gerada só para teste. O contrato
//! de wire foi extraído do motor (`remoteid-aplicacao`) e do servidor enlatado de
//! `crates/remoteid-aplicacao/tests/fluxo.rs` — ver os comentários por endpoint.
//!
//! Uso: `remoteid-mock [porta]` (padrão 8799). O app entra em modo de teste
//! com `TEST_URL=http://localhost:8799`.
//!
//! Credenciais fixas de teste:
//! - e-mail `teste@remoteid.local`, senha `teste-1234`
//! - PIN `1234`, OTP `123456`

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use der::Decode;
use remoteid_cripto::{b64, de_b64, ChaveInstalacao};
use serde_json::{json, Value};
use x509_cert::Certificate;

// Fixtures embutidas (geradas por openssl; ver crates/remoteid-mock/fixtures).
const CHAVE_PEM: &str = include_str!("../fixtures/fake-key.pem");
const CERT_DER: &[u8] = include_bytes!("../fixtures/fake-cert.der");

// Credenciais fixas que o mock aceita (só teste).
const EMAIL_OK: &str = "teste@remoteid.local";
const SENHA_OK: &str = "teste-1234";
const PIN_OK: &str = "1234";
const OTP_OK: &str = "123456";

// O emissor no formato em que o servidor REAL devolve no JSON da carteira:
// vírgula-espaço, do CN para o C. Fica literal porque é paridade de protocolo,
// não um detalhe do nosso certificado — mas `conferir_emissor` garante que a
// AC das fixtures é mesmo esta. Antes de 04/09/2026 o certificado era
// autoassinado pelo TITULAR, então este campo e o DER se contradiziam.
const ISSUER: &str = "CN=AC TESTE DESKTOPID, OU=AC TESTE RAIZ, O=ICP-Brasil TESTE, C=BR";

/// O serial do certificado embutido, em hex maiúsculo — como a Certisign
/// devolve no `keyName`.
///
/// Lido do DER, não fixado numa constante: regerar as fixtures muda o serial, e
/// uma constante desatualizada faria o mock anunciar na carteira um certificado
/// diferente do que ele entrega. O bug seria silencioso e só apareceria como
/// "assinatura não confere".
fn serial_do_cert(der: &[u8]) -> String {
    let cert = Certificate::from_der(der).expect("certificado falso embutido inválido");
    cert.tbs_certificate
        .serial_number
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Falha cedo e alto se as fixtures forem regeradas com outra AC.
///
/// O `ISSUER` acima é literal por paridade de protocolo; esta função é o que
/// impede ele de virar mentira. Compara os valores dos RDNs, não a string
/// inteira, porque a formatação do `x509-cert` (RFC 4514, sem espaço após a
/// vírgula) não é a do servidor real.
fn conferir_emissor(der: &[u8]) {
    let cert = Certificate::from_der(der).expect("certificado falso embutido inválido");
    let emissor = cert.tbs_certificate.issuer.to_string();
    for parte in ["AC TESTE DESKTOPID", "AC TESTE RAIZ", "ICP-Brasil TESTE", "BR"] {
        assert!(
            emissor.contains(parte),
            "as fixtures foram regeradas com outra AC: o DER diz {emissor:?}, \
             mas a constante ISSUER promete {ISSUER:?}. \
             Rode tools/gerar-fixtures-mock.sh ou ajuste a constante."
        );
    }
}
const CODIGO_DESKTOP: &str = "4d1f71d2-c20b-44d0-9bb0-5629015f21e8";
const JWT_FALSO: &str = "jwt.do.login";

fn main() {
    let porta: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(8799);

    let chave = ChaveInstalacao::de_pem(CHAVE_PEM).expect("chave falsa embutida inválida");
    let cert_b64 = b64(CERT_DER);
    conferir_emissor(CERT_DER);
    let serial = serial_do_cert(CERT_DER);

    let listener = TcpListener::bind(("127.0.0.1", porta))
        .unwrap_or_else(|e| panic!("não consegui abrir 127.0.0.1:{porta}: {e}"));
    eprintln!("remoteid-mock ouvindo em http://localhost:{porta}");
    eprintln!("  login: {EMAIL_OK} / {SENHA_OK}   PIN: {PIN_OK}   OTP: {OTP_OK}");
    eprintln!("  rode o app com: TEST_URL=http://localhost:{porta} remoteid-app");

    for conexao in listener.incoming() {
        match conexao {
            Ok(fluxo) => {
                if let Err(e) = atender(fluxo, &chave, &cert_b64, &serial) {
                    eprintln!("  [erro ao atender] {e}");
                }
            }
            Err(_) => continue,
        }
    }
}

fn atender(
    mut fluxo: TcpStream,
    chave: &ChaveInstalacao,
    cert_b64: &str,
    serial: &str,
) -> std::io::Result<()> {
    let mut leitor = BufReader::new(fluxo.try_clone()?);

    // Linha de request: "POST /caminho HTTP/1.1".
    let mut linha = String::new();
    if leitor.read_line(&mut linha)? == 0 {
        return Ok(());
    }
    let caminho = linha.split_whitespace().nth(1).unwrap_or("/").to_string();

    // Cabeçalhos: só precisamos do Content-Length.
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if leitor.read_line(&mut h)? == 0 {
            break;
        }
        if h == "\r\n" || h == "\n" {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    // Corpo.
    let mut corpo = vec![0u8; content_length];
    if content_length > 0 {
        leitor.read_exact(&mut corpo)?;
    }
    let corpo_json: Value = serde_json::from_slice(&corpo).unwrap_or(Value::Null);

    let resposta = rotear(&caminho, &corpo_json, chave, cert_b64, serial);
    eprintln!("  {caminho} -> {}", resumo(&resposta));

    responder(&mut fluxo, &resposta)
}

/// Roteamento por SUFIXO do path (o motor usa paths com placeholders; o mock,
/// como o servidor enlatado dos testes, casa pelo fim). Sempre HTTP 200: o erro
/// de negócio vai no corpo (`status:false`), que é como a Certisign responde.
fn rotear(
    caminho: &str,
    corpo: &Value,
    chave: &ChaveInstalacao,
    cert_b64: &str,
    serial: &str,
) -> Value {
    if caminho.ends_with("/usrsenha") {
        // 1. login. Sem campo `status`; o motor exige `token`. Credenciais
        // erradas → sem token → o motor falha com "token ausente".
        let email = corpo.get("email").and_then(Value::as_str).unwrap_or("");
        let senha = corpo.get("senha").and_then(Value::as_str).unwrap_or("");
        if email == EMAIL_OK && senha == SENHA_OK {
            json!({
                "id": 327989, "organizacaoId": 0,
                "nome": "JOÃO GONÇALVES DE ASSUNÇÃO", "cpf": "11111111111",
                "token": JWT_FALSO
            })
        } else {
            json!({ "message": "credenciais inválidas (use as fixas de teste)" })
        }
    } else if caminho.contains("/usuario/") && caminho.contains("/organizacao/") {
        // 2. registrar desktop. Auth = Bearer JWT; o mock não valida a fundo.
        json!({ "codigoDesktop": CODIGO_DESKTOP, "id": 12345 })
    } else if caminho.ends_with("/carteira") {
        // 3. carteira: devolve o certificado falso. keyName = "<serial>;<issuer>".
        json!({ "certificados": [ {
            "keyName": format!("{serial};{ISSUER}"),
            "base64": cert_b64
        } ] })
    } else if caminho.ends_with("/statusCelular") {
        // 4. statusCelular: informativo; o motor grava mas não decide por ele.
        json!({ "usuarioPossuiCodigoPush": false })
    } else if caminho.ends_with("/tokensessao") {
        // 5. tokensessao: exige PIN e OTP fixos. O token é opaco; o motor só
        // extrai o penúltimo campo (epoch) para o pré-filtro de cache.
        let pin = corpo.get("pin").and_then(Value::as_str).unwrap_or("");
        let otp = corpo.get("otp").and_then(Value::as_str).unwrap_or("");
        if pin != PIN_OK {
            json!({ "status": false, "message": "Informe o Pin correto (teste: 1234)", "token": null })
        } else if otp != OTP_OK {
            json!({ "status": false, "message": "Informe o e-Token(Otp) correto (teste: 123456)", "token": null })
        } else {
            let epoch = agora();
            let token =
                format!("sessaoAssinatura;327989;CN%3DAC%20TESTE;{serial};0;ZXlK;{epoch};hmac=");
            json!({ "status": true, "message": "Token gerado com sucesso", "token": token })
        }
    } else if caminho.ends_with("/requestHashSessionSignature") {
        // 6. requestHash: assina o digest recebido com a chave FALSA, para a
        // assinatura verificar contra o certificado falso. idArray[0].id volta
        // como STRING (assimetria do backend real, reproduzida aqui).
        match assinar_hash(corpo, chave) {
            Ok(sig_b64) => json!({
                "status": true,
                "message": "Requisição de assinatura no Hsm realizada com sucesso.",
                "idArray": [ {
                    "id": "0", "status": true,
                    "message": "Assinatura no hsm gerada com sucesso.",
                    "signatureBase64": sig_b64
                } ]
            }),
            Err(msg) => json!({ "status": false, "message": msg, "idArray": [] }),
        }
    } else if caminho.contains("listHierarchies") || caminho.contains("/CertisignerServices/") {
        // Check de conectividade (certinext). Só precisa de um 200 são.
        json!({ "status": true })
    } else {
        json!({ "status": false, "message": format!("rota não enlatada: {caminho}") })
    }
}

/// Extrai `hashArray[0].hash` (base64 de 32 bytes), assina com a chave falsa
/// (PKCS#1 v1.5 sobre SHA-256 — o que o HSM faz) e devolve base64 dos 256 bytes.
fn assinar_hash(corpo: &Value, chave: &ChaveInstalacao) -> Result<String, String> {
    let hash_b64 = corpo
        .get("hashArray")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|item| item.get("hash"))
        .and_then(Value::as_str)
        .ok_or("hashArray[0].hash ausente")?;
    let digest = de_b64(hash_b64).map_err(|e| format!("hash não é base64: {e}"))?;
    if digest.len() != 32 {
        return Err(format!(
            "digest tem que ter 32 bytes, veio com {}",
            digest.len()
        ));
    }
    let assinatura = chave
        .assinar_digest(&digest)
        .map_err(|e| format!("falha ao assinar: {e}"))?;
    Ok(b64(&assinatura))
}

fn agora() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn resumo(v: &Value) -> String {
    if let Some(false) = v.get("status").and_then(Value::as_bool) {
        format!(
            "ERRO: {}",
            v.get("message").and_then(Value::as_str).unwrap_or("?")
        )
    } else if v.get("certificados").is_some() {
        "OK (carteira: 1 certificado)".to_string()
    } else if v.get("idArray").is_some() {
        "OK (assinatura gerada)".to_string()
    } else if v.get("token").and_then(Value::as_str).is_some() {
        // tokensessao traz `status:true`; login não tem `status`.
        if v.get("status").is_some() {
            "OK (tokensessao)".to_string()
        } else {
            "OK (login)".to_string()
        }
    } else {
        "OK".to_string()
    }
}

fn responder(fluxo: &mut TcpStream, corpo: &Value) -> std::io::Result<()> {
    let texto = corpo.to_string();
    let cabecalho = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        texto.len()
    );
    fluxo.write_all(cabecalho.as_bytes())?;
    fluxo.write_all(texto.as_bytes())?;
    fluxo.flush()
}
