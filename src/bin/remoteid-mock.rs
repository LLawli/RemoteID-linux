//! Servidor RemoteID falso, para testar tudo sem a conta real nem a Certisign.
//!
//! `remoteid-mock [porta]` (padrão 8799; 0 escolhe uma livre). A primeira
//! linha da saída padrão é o endereço, para quem o sobe em teste. O cliente
//! fala com ele com `REMOTEID_SERVIDOR=<endereço>`.
//!
//! Aceita só as credenciais de teste: `teste@remoteid.local` / `teste-1234`,
//! OTP `123456`. Como no servidor real, o "pin" da sessão de assinatura é a
//! senha da conta. Responde como o servidor real, nas formas medidas
//! (HTTP 200 com `status: false` no erro de negócio), e é mais estrito que um
//! servidor que só devolve respostas prontas: confere o `Bearer` de cada
//! requisição de operação com a chave pública do registro, e lembra as
//! sessões abertas. `POST /_mock/expirar` esquece todas, como o servidor faz
//! quando uma sessão vence.
//!
//! Os literais de `algorithm` e as mensagens de erro ficam aqui, e não vêm do
//! cliente: o servidor falso é o oráculo do que foi medido no real.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use sha2::Sha256;

use remoteid::cripto::{b64, de_b64, sha256};
use remoteid::protocolo::canonica::canonica;

const CHAVE_TITULAR: &str = include_str!("../../tests/mock/fake-key.pem");
const CERTIFICADO: &[u8] = include_bytes!("../../tests/mock/fake-cert.der");
const CADEIA: &[u8] = include_bytes!("../../tests/mock/AC_TESTE_DESKTOPID.p7c");
const SERIAL: &str = "16C3F7EFA6CCE55817FA659DC8EAA29B7E512621";
const EMISSOR: &str = "CN=AC TESTE DESKTOPID, O=ICP-Brasil TESTE, C=BR";

const EMAIL: &str = "teste@remoteid.local";
const SENHA: &str = "teste-1234";
const OTP: &str = "123456";
const JWT: &str = "jwt.do.login";
const CODIGO_DESKTOP: &str = "4d1f71d2-c20b-44d0-9bb0-5629015f21e8";

// As mensagens do servidor real.
const RECUSA_FATOR: &str = "PIN ou e-Token incorreto";
const RECUSA_BEARER: &str = "Código de autorização inválida";
const SEM_SESSAO: &str = "Não existe autorização válida para este token";
const RECUSA_ASSINATURA: &str = "Erro ao gerar assinatura RSA.";

#[derive(Default)]
struct Servidor {
    /// A chave pública que o registro entregou: a única que assina `Bearer`.
    instalacao: Option<RsaPublicKey>,
    sessoes: HashSet<String>,
}

fn main() {
    let porta: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8799);
    let ouvinte = TcpListener::bind(("127.0.0.1", porta))
        .unwrap_or_else(|e| panic!("não abriu 127.0.0.1:{porta}: {e}"));
    println!("http://{}", ouvinte.local_addr().unwrap());
    std::io::stdout().flush().unwrap();
    eprintln!("login {EMAIL} / {SENHA}, OTP {OTP}");

    let titular = RsaPrivateKey::from_pkcs8_pem(CHAVE_TITULAR).unwrap();
    let mut servidor = Servidor::default();
    for conexao in ouvinte.incoming().flatten() {
        if let Err(e) = atender(conexao, &mut servidor, &titular) {
            eprintln!("erro ao atender: {e}");
        }
    }
}

fn atender(
    mut conexao: TcpStream,
    servidor: &mut Servidor,
    titular: &RsaPrivateKey,
) -> std::io::Result<()> {
    let mut leitor = BufReader::new(conexao.try_clone()?);
    let mut linha = String::new();
    leitor.read_line(&mut linha)?;
    let caminho = linha.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut tamanho = 0;
    let mut autorizacao = String::new();
    loop {
        let mut cabecalho = String::new();
        if leitor.read_line(&mut cabecalho)? == 0 || cabecalho.trim().is_empty() {
            break;
        }
        let (nome, valor) = cabecalho.split_once(':').unwrap_or_default();
        match nome.trim().to_ascii_lowercase().as_str() {
            "content-length" => tamanho = valor.trim().parse().unwrap_or(0),
            "authorization" => autorizacao = valor.trim().to_string(),
            _ => {}
        }
    }
    let mut corpo = vec![0; tamanho];
    leitor.read_exact(&mut corpo)?;

    if caminho.ends_with(".p7c") {
        return responder(&mut conexao, 200, "application/pkcs7-mime", CADEIA);
    }
    let corpo: Value = serde_json::from_slice(&corpo).unwrap_or(Value::Null);
    let (http, resposta) = rotear(&caminho, &corpo, &autorizacao, servidor, titular);
    eprintln!(
        "{caminho} -> {http} {}",
        resposta.get("message").unwrap_or(&Value::Null)
    );
    responder(
        &mut conexao,
        http,
        "application/json",
        resposta.to_string().as_bytes(),
    )
}

fn rotear(
    caminho: &str,
    corpo: &Value,
    autorizacao: &str,
    servidor: &mut Servidor,
    titular: &RsaPrivateKey,
) -> (u16, Value) {
    let texto = |chave: &str| corpo.get(chave).and_then(Value::as_str).unwrap_or("");
    let recusa = |mensagem: &str| (200, json!({"status": false, "message": mensagem}));

    if caminho == "/_mock/expirar" {
        servidor.sessoes.clear();
        return (200, json!({"status": true}));
    }
    if caminho.ends_with("/listHierarchies") {
        return (200, json!({"status": true}));
    }
    if caminho.ends_with("/login/usrsenha") {
        return if texto("email") == EMAIL && texto("senha") == SENHA {
            (
                200,
                json!({"id": 327989, "organizacaoId": 0, "nome": "TESTE DESKTOPID",
                    "cpf": "00000000000", "token": JWT}),
            )
        } else {
            (
                500,
                json!({"exception": "UsuarioSenhaInvalidoException",
                    "message": "Usuário ou senha inválidos"}),
            )
        };
    }
    if caminho.contains("/usuario/") && caminho.contains("/organizacao/") {
        if autorizacao != format!("Bearer {JWT}") {
            return (401, json!({"message": "JWT inválido"}));
        }
        if texto("dominioRede").is_empty() {
            return (500, json!({"message": "DomainNameLeftBlank"}));
        }
        let Ok(chave) = RsaPublicKey::from_public_key_pem(texto("chavePublica")) else {
            return (500, json!({"message": "ConstraintViolation: chavePublica"}));
        };
        servidor.instalacao = Some(chave);
        return (200, json!({"codigoDesktop": CODIGO_DESKTOP, "id": 12345}));
    }

    // Daqui em diante, só com o Bearer da chave do registro.
    if !bearer_confere(servidor, corpo, autorizacao) {
        return recusa(RECUSA_BEARER);
    }
    if caminho.ends_with("/statusCelular") {
        return (
            200,
            json!({"status": true, "usuarioPossuiCodigoPush": false}),
        );
    }
    if caminho.ends_with("/carteira") {
        let key_name = format!("{SERIAL};{EMISSOR}");
        return (
            200,
            json!({"status": true, "certificados": [{"keyName": key_name, "base64": b64(CERTIFICADO)}]}),
        );
    }
    if caminho.ends_with("/tokensessao") {
        if texto("pin") != SENHA || texto("otp") != OTP {
            return (
                200,
                json!({"status": false, "message": RECUSA_FATOR, "token": null}),
            );
        }
        let token = format!(
            "sessaoAssinatura;327989;CN%3DAC%20TESTE;{SERIAL};0;ZXlK;{};hmac=",
            agora()
        );
        servidor.sessoes.insert(token.clone());
        return (
            200,
            json!({"status": true, "message": "Token gerado com sucesso", "token": token}),
        );
    }
    if caminho.ends_with("/requestHashSessionSignature") {
        if !servidor.sessoes.contains(texto("sessionToken")) {
            return recusa(SEM_SESSAO);
        }
        return match assinar(corpo, titular) {
            Some(assinatura) => (
                200,
                json!({"status": true, "idArray": [{"id": "0", "status": true,
                    "signatureBase64": b64(&assinatura)}]}),
            ),
            // A forma medida em 05/09/2026: os campos de sucesso vêm nulos.
            None => (
                200,
                json!({"certificate": null, "idArray": null, "message": RECUSA_ASSINATURA,
                    "status": false}),
            ),
        };
    }
    recusa(&format!("rota desconhecida: {caminho}"))
}

fn bearer_confere(servidor: &Servidor, corpo: &Value, autorizacao: &str) -> bool {
    let (Some(chave), Some(assinatura)) = (
        &servidor.instalacao,
        autorizacao.strip_prefix("Bearer ").and_then(de_b64),
    ) else {
        return false;
    };
    let digest = sha256(canonica(corpo).as_bytes());
    chave
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &assinatura)
        .is_ok()
}

/// Assina como o HSM, nos dois modos medidos: `"SHA256"` recebe o hash de 32
/// bytes e embrulha em DigestInfo; `""` recebe o bloco pronto (1 a 245 bytes)
/// e só aplica o padding. Qualquer outro valor é recusado.
fn assinar(corpo: &Value, titular: &RsaPrivateKey) -> Option<Vec<u8>> {
    let bloco = corpo["hashArray"][0]["hash"].as_str().and_then(de_b64)?;
    let esquema = match corpo["algorithm"].as_str()? {
        "SHA256" if bloco.len() == 32 => Pkcs1v15Sign::new::<Sha256>(),
        "" if (1..=245).contains(&bloco.len()) => Pkcs1v15Sign::new_unprefixed(),
        _ => return None,
    };
    titular.sign(esquema, &bloco).ok()
}

fn agora() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn responder(conexao: &mut TcpStream, http: u16, tipo: &str, corpo: &[u8]) -> std::io::Result<()> {
    let cabeca = format!(
        "HTTP/1.1 {http} X\r\nContent-Type: {tipo}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        corpo.len()
    );
    conexao.write_all(cabeca.as_bytes())?;
    conexao.write_all(corpo)?;
    conexao.flush()
}
