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
//!
//! `REMOTEID_MOCK_FIXTURES=<dir>` troca o certificado embutido pelo de um
//! diretório de fora (`cert.der`, `key.pem`, `keyname.txt`), para rodar contra
//! uma carteira com a forma e o conteúdo de uma real sem que esse material
//! encoste no repositório. Ver [`Carteira::carregar`].

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use remoteid_cripto::{b64, de_b64, ChaveInstalacao};
use serde_json::{json, Value};

// Fixtures embutidas (geradas por openssl; ver crates/remoteid-mock/fixtures).
const CHAVE_PEM: &str = include_str!("../fixtures/fake-key.pem");
const CERT_DER: &[u8] = include_bytes!("../fixtures/fake-cert.der");

/// Diretório com `cert.der`, `key.pem` e `keyname.txt` que substituem as
/// fixtures embutidas. Ver [`Carteira::carregar`].
const ENV_FIXTURES: &str = "REMOTEID_MOCK_FIXTURES";

// Credenciais fixas que o mock aceita (só teste).
const EMAIL_OK: &str = "teste@remoteid.local";
const SENHA_OK: &str = "teste-1234";
const PIN_OK: &str = "1234";
const OTP_OK: &str = "123456";

// Metadados do certificado falso (o serial bate com o `fake-cert.der`).
const SERIAL: &str = "5555DC3AA6C69D58EDBA3A7F9C682E12719E1804";
const ISSUER: &str = "CN=AC TESTE DESKTOPID, O=ICP-Brasil TESTE, C=BR";
const CODIGO_DESKTOP: &str = "4d1f71d2-c20b-44d0-9bb0-5629015f21e8";
const JWT_FALSO: &str = "jwt.do.login";

/// O que o mock publica na carteira e usa para assinar: o certificado, a chave
/// que casa com ele, e o `keyName` (`"<serial>;<issuer>"`) que o servidor real
/// devolveria. O serial também vai no `tokensessao`, por isso sai do MESMO
/// lugar que o `keyName`: as duas respostas não podem discordar.
struct Carteira {
    chave: ChaveInstalacao,
    cert_b64: String,
    key_name: String,
    serial: String,
}

impl Carteira {
    /// Sem `REMOTEID_MOCK_FIXTURES`, as fixtures SINTÉTICAS embutidas. Com ela,
    /// um diretório de fora com `cert.der`, `key.pem` e `keyname.txt`.
    ///
    /// Existe porque um certificado de verdade tem forma e conteúdo que a
    /// fixture sintética não reproduz (as extensões da ICP-Brasil, os OUs, os
    /// acentos do titular), e é justamente aí que aparecem os bugs de parsing e
    /// de tela. O material real carrega dado pessoal e **nunca** entra no
    /// repositório: por isso ele mora fora, e o mock só recebe o caminho.
    ///
    /// Com a variável posta e o diretório imprestável, o mock MORRE. Cair de
    /// volta na fixture embutida deixaria o teste verde exibindo outra
    /// identidade, que é o pior resultado possível: verde sem provar nada.
    fn carregar() -> Self {
        match std::env::var_os(ENV_FIXTURES) {
            Some(dir) if !dir.is_empty() => Self::de_diretorio(Path::new(&dir)),
            _ => Self::embutida(),
        }
    }

    fn embutida() -> Self {
        Self {
            chave: ChaveInstalacao::de_pem(CHAVE_PEM).expect("chave falsa embutida inválida"),
            cert_b64: b64(CERT_DER),
            key_name: format!("{SERIAL};{ISSUER}"),
            serial: SERIAL.to_string(),
        }
    }

    fn de_diretorio(dir: &Path) -> Self {
        let ler = |nome: &str| -> Vec<u8> {
            let caminho: PathBuf = dir.join(nome);
            std::fs::read(&caminho).unwrap_or_else(|e| {
                panic!(
                    "{ENV_FIXTURES}: não consegui ler {}: {e}",
                    caminho.display()
                )
            })
        };
        let chave_pem = String::from_utf8(ler("key.pem"))
            .unwrap_or_else(|_| panic!("{ENV_FIXTURES}: key.pem não é texto"));
        let cert_der = ler("cert.der");
        let key_name = String::from_utf8(ler("keyname.txt"))
            .unwrap_or_else(|_| panic!("{ENV_FIXTURES}: keyname.txt não é texto"))
            .trim()
            .to_string();

        // Conferir o artefato, não só a leitura: um cert.der truncado passaria
        // no `read` e só explodiria dentro do app, longe daqui.
        assert!(
            cert_der.len() > 300,
            "{ENV_FIXTURES}: cert.der tem {} bytes, tamanho implausível para um X.509",
            cert_der.len()
        );
        let serial = key_name.split(';').next().unwrap_or_default().to_string();
        assert!(
            !serial.is_empty() && key_name.contains(';'),
            "{ENV_FIXTURES}: keyname.txt tem que ser \"<serial>;<issuer>\""
        );

        Self {
            chave: ChaveInstalacao::de_pem(&chave_pem)
                .unwrap_or_else(|e| panic!("{ENV_FIXTURES}: key.pem inválida: {e}")),
            cert_b64: b64(&cert_der),
            key_name,
            serial,
        }
    }
}

fn main() {
    let porta: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(8799);

    let carteira = Carteira::carregar();

    let listener = TcpListener::bind(("127.0.0.1", porta))
        .unwrap_or_else(|e| panic!("não consegui abrir 127.0.0.1:{porta}: {e}"));
    eprintln!("remoteid-mock ouvindo em http://localhost:{porta}");
    eprintln!("  login: {EMAIL_OK} / {SENHA_OK}   PIN: {PIN_OK}   OTP: {OTP_OK}");
    // O serial identifica a carteira sem dizer de quem ela é: o `keyName`
    // inteiro traz o emissor, e o certificado, o titular.
    match std::env::var_os(ENV_FIXTURES) {
        Some(dir) if !dir.is_empty() => eprintln!(
            "  carteira de {} (serial {})",
            Path::new(&dir).display(),
            carteira.serial
        ),
        _ => eprintln!("  carteira: fixtures sintéticas embutidas"),
    }
    eprintln!("  rode o app com: TEST_URL=http://localhost:{porta} remoteid-app");

    for conexao in listener.incoming() {
        match conexao {
            Ok(fluxo) => {
                if let Err(e) = atender(fluxo, &carteira) {
                    eprintln!("  [erro ao atender] {e}");
                }
            }
            Err(_) => continue,
        }
    }
}

fn atender(mut fluxo: TcpStream, carteira: &Carteira) -> std::io::Result<()> {
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

    let resposta = rotear(&caminho, &corpo_json, carteira);
    eprintln!("  {caminho} -> {}", resumo(&resposta));

    responder(&mut fluxo, &resposta)
}

/// Roteamento por SUFIXO do path (o motor usa paths com placeholders; o mock,
/// como o servidor enlatado dos testes, casa pelo fim). Sempre HTTP 200: o erro
/// de negócio vai no corpo (`status:false`), que é como a Certisign responde.
fn rotear(caminho: &str, corpo: &Value, carteira: &Carteira) -> Value {
    if caminho.ends_with("/usrsenha") {
        // 1. login. Sem campo `status`; o motor exige `token`. Credenciais
        // erradas → sem token → o motor falha com "token ausente".
        let email = corpo.get("email").and_then(Value::as_str).unwrap_or("");
        let senha = corpo.get("senha").and_then(Value::as_str).unwrap_or("");
        if email == EMAIL_OK && senha == SENHA_OK {
            json!({
                "id": 327989, "organizacaoId": 0,
                "nome": "TESTE DESKTOPID", "cpf": "00000000000",
                "token": JWT_FALSO
            })
        } else {
            json!({ "message": "credenciais inválidas (use as fixas de teste)" })
        }
    } else if caminho.contains("/usuario/") && caminho.contains("/organizacao/") {
        // 2. registrar desktop. Auth = Bearer JWT; o mock não valida a fundo.
        json!({ "codigoDesktop": CODIGO_DESKTOP, "id": 12345 })
    } else if caminho.ends_with("/carteira") {
        // 3. carteira: devolve o certificado do mock. keyName = "<serial>;<issuer>".
        json!({ "certificados": [ {
            "keyName": carteira.key_name,
            "base64": carteira.cert_b64
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
            let serial = &carteira.serial;
            let token =
                format!("sessaoAssinatura;327989;CN%3DAC%20TESTE;{serial};0;ZXlK;{epoch};hmac=");
            json!({ "status": true, "message": "Token gerado com sucesso", "token": token })
        }
    } else if caminho.ends_with("/requestHashSessionSignature") {
        // 6. requestHash: assina o que veio com a chave FALSA, para a
        // assinatura verificar contra o certificado falso. idArray[0].id volta
        // como STRING (assimetria do backend real, reproduzida aqui). A recusa
        // tem a forma medida ao vivo em 05/09/2026: `certificate` e `idArray`
        // presentes como null, HTTP 200.
        match assinar_hash(corpo, &carteira.chave) {
            Ok(sig_b64) => json!({
                "status": true,
                "message": "Requisição de assinatura no Hsm realizada com sucesso.",
                "idArray": [ {
                    "id": "0", "status": true,
                    "message": "Assinatura no hsm gerada com sucesso.",
                    "signatureBase64": sig_b64
                } ]
            }),
            Err(msg) => json!({
                "certificate": null, "idArray": null,
                "message": msg, "status": false
            }),
        }
    } else if caminho.contains("listHierarchies") || caminho.contains("/CertisignerServices/") {
        // Check de conectividade (certinext). Só precisa de um 200 são.
        json!({ "status": true })
    } else {
        json!({ "status": false, "message": format!("rota não enlatada: {caminho}") })
    }
}

/// A mensagem de recusa do servidor real, medida com `algorithm: "MD5"`.
const ERRO_ASSINATURA: &str = "Erro ao gerar assinatura RSA.";

/// Extrai `hashArray[0].hash` e `algorithm`, e assina com a chave falsa do
/// jeito que o HSM faz em cada modo (sondagem ao vivo de 05/09/2026):
///
/// - `"SHA256"`: o hash tem 32 bytes; embrulha em DigestInfo(SHA-256) e assina.
/// - `""` (vazio): modo CRU; o bloco (1 a 245 bytes) só recebe o padding
///   PKCS#1 v1.5. É o que assina o DigestInfo(MD5) do PJeOffice.
/// - qualquer outro valor: recusa com a mensagem do servidor real. (O real
///   também honra `"SHA1"` por nome; o cliente não emite, o mock não imita.)
///
/// Os literais ficam AQUI, de propósito, e não vêm do domínio do cliente: o
/// mock é o oráculo do que foi medido no servidor, e se o cliente errar o
/// literal, o gate tem de ficar vermelho, não concordar.
fn assinar_hash(corpo: &Value, chave: &ChaveInstalacao) -> Result<String, String> {
    let hash_b64 = corpo
        .get("hashArray")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|item| item.get("hash"))
        .and_then(Value::as_str)
        .ok_or("hashArray[0].hash ausente")?;
    let algorithm = corpo
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or("algorithm ausente")?;
    let bloco = de_b64(hash_b64).map_err(|e| format!("hash não é base64: {e}"))?;
    let assinatura = match algorithm {
        "SHA256" if bloco.len() == 32 => chave.assinar_digest(&bloco),
        "" if !bloco.is_empty() && bloco.len() <= 245 => chave.assinar_pkcs1_v15_cru(&bloco),
        _ => return Err(ERRO_ASSINATURA.to_string()),
    }
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
