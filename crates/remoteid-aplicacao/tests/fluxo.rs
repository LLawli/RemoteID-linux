//! Fluxo completo contra um servidor local que devolve respostas enlatadas.
//!
//! Sem isto, a única forma de exercitar o motor seria com a conta real de um
//! testador, gastando um OTP por tentativa. O que estes testes travam:
//!
//! - o corpo exato de cada passo (é a paridade com o app oficial);
//! - que o `Authorization` de cada operação é MESMO a assinatura da canônica
//!   daquele corpo, verificável com a chave pública da instalação;
//! - que o motor devolve o bloco RSA cru, e não o base64.
//!
//! O servidor é HTTP simples: as URLs são parametrizáveis justamente para isto.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use remoteid_aplicacao::{Motor, Opcoes};
use remoteid_autorizacao::{Fatores, Modo};
use remoteid_cripto::{b64, de_b64, sha256};
use remoteid_protocolo_servidor::canonical::canonical;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
struct Requisicao {
    caminho: String,
    autorizacao: Option<String>,
    corpo: Value,
}

struct Servidor {
    base: String,
    recebidas: Arc<Mutex<Vec<Requisicao>>>,
}

impl Servidor {
    /// Sobe o servidor com um mapa de caminho → resposta JSON.
    fn subir(respostas: HashMap<String, Value>) -> Servidor {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let porta = listener.local_addr().unwrap().port();
        let recebidas = Arc::new(Mutex::new(Vec::new()));
        let registro = Arc::clone(&recebidas);

        std::thread::spawn(move || {
            for fluxo in listener.incoming() {
                let Ok(fluxo) = fluxo else { continue };
                let _ = atender(fluxo, &respostas, &registro);
            }
        });

        Servidor {
            base: format!("http://127.0.0.1:{porta}"),
            recebidas,
        }
    }

    fn requisicao(&self, sufixo: &str) -> Requisicao {
        self.recebidas
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.caminho.ends_with(sufixo))
            .unwrap_or_else(|| panic!("nenhuma requisição para {sufixo}"))
            .clone()
    }
}

fn atender(
    mut fluxo: TcpStream,
    respostas: &HashMap<String, Value>,
    registro: &Arc<Mutex<Vec<Requisicao>>>,
) -> std::io::Result<()> {
    let mut leitor = BufReader::new(fluxo.try_clone()?);

    let mut linha = String::new();
    leitor.read_line(&mut linha)?;
    let caminho = linha.split_whitespace().nth(1).unwrap_or("/").to_string();

    let mut tamanho = 0usize;
    let mut autorizacao = None;
    loop {
        let mut h = String::new();
        if leitor.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        let baixo = h.to_lowercase();
        if let Some(v) = baixo.strip_prefix("content-length:") {
            tamanho = v.trim().parse().unwrap_or(0);
        }
        if baixo.starts_with("authorization:") {
            autorizacao = Some(h["authorization:".len()..].trim().to_string());
        }
    }

    let mut corpo_bruto = vec![0u8; tamanho];
    if tamanho > 0 {
        leitor.read_exact(&mut corpo_bruto)?;
    }
    let corpo: Value = serde_json::from_slice(&corpo_bruto).unwrap_or(Value::Null);

    registro.lock().unwrap().push(Requisicao {
        caminho: caminho.clone(),
        autorizacao,
        corpo,
    });

    let resposta = respostas
        .iter()
        .find(|(k, _)| caminho.ends_with(k.as_str()))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| json!({"status": false, "message": "rota não enlatada"}));
    let texto = resposta.to_string();

    write!(
        fluxo,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        texto.len(),
        texto
    )?;
    fluxo.flush()
}

const CODIGO_DESKTOP: &str = "4d1f71d2-c20b-44d0-9bb0-5629015f21e8";
const KEY_NAME: &str = "12CC6B560ECE122AC1047AA7BE71DBC3;CN=AC OAB G3, O=ICP-Brasil, C=BR";

/// A assinatura que o HSM devolveria: 256 bytes, como na run real.
fn assinatura_falsa() -> Vec<u8> {
    (0..256u32).map(|i| (i % 251) as u8).collect()
}

fn respostas_padrao() -> HashMap<String, Value> {
    let mut m = HashMap::new();
    m.insert(
        "/login/usrsenha".to_string(),
        json!({"id": 327989, "organizacaoId": 0, "nome": "Fulano de Tal",
               "cpf": "00000000000", "token": "jwt.do.login"}),
    );
    m.insert(
        "/usuario/327989/organizacao/0".to_string(),
        json!({"codigoDesktop": CODIGO_DESKTOP, "id": 12345}),
    );
    m.insert(
        "/carteira".to_string(),
        json!({"certificados": [{"keyName": KEY_NAME, "base64": "TUlJRA=="}]}),
    );
    m.insert(
        "/statusCelular".to_string(),
        json!({"usuarioPossuiCodigoPush": true}),
    );
    m.insert(
        "/tokensessao".to_string(),
        json!({"status": true, "message": "Token gerado com sucesso",
               "token": "sessaoAssinatura;327989;CN%3DAC;SER;0;ZXlK;1788393969;hmac="}),
    );
    m.insert(
        "/requestHashSessionSignature".to_string(),
        json!({"status": true, "message": "Requisição de assinatura no Hsm realizada com sucesso.",
               "idArray": [{"id": "0", "status": true,
                            "message": "Assinatura no hsm gerada com sucesso.",
                            "signatureBase64": b64(&assinatura_falsa())}]}),
    );
    m
}

struct Ambiente {
    dir: std::path::PathBuf,
}

impl Ambiente {
    fn novo(nome: &str) -> Ambiente {
        let dir = std::env::temp_dir().join(format!("dtid-it-{nome}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Ambiente { dir }
    }
    fn opcoes(&self, base: &str) -> Opcoes {
        Opcoes {
            dir_dados: self.dir.join("dados"),
            dir_diag: self.dir.join("diag"),
            remoteid_url: base.to_string(),
            certinext_url: base.to_string(),
            timeout: Duration::from_secs(10),
            ttl_sessao_hipotetico_s: 15 * 60,
        }
    }
}

impl Drop for Ambiente {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Prepara o motor até o ponto de assinar.
fn motor_preparado(amb: &Ambiente, srv: &Servidor) -> Motor {
    let mut motor = Motor::abrir(amb.opcoes(&srv.base)).unwrap();
    motor.login("teste@exemplo.br", "senha").unwrap();
    motor.registrar("maquina-de-teste").unwrap();
    motor.carteira().unwrap();
    motor
}

/// Confere que o Bearer daquela requisição é a assinatura da canônica do corpo.
fn conferir_bearer(amb: &Ambiente, req: &Requisicao) {
    let chave =
        remoteid_chave_pem::carregar(&remoteid_caminhos::caminho_chave(&amb.dir.join("dados")))
            .unwrap();
    let bearer = req
        .autorizacao
        .as_ref()
        .expect("requisição de operação sem Authorization")
        .strip_prefix("Bearer ")
        .expect("Authorization sem o prefixo Bearer")
        .to_string();

    // O JWT do login tem pontos; a assinatura é base64 puro. Foi exatamente
    // essa confusão que produzia "Illegal base64 character 2e" no servidor.
    assert!(
        !bearer.contains('.'),
        "mandou o JWT onde vai a assinatura: {bearer}"
    );

    let assinatura = de_b64(&bearer).expect("Bearer não é base64");
    assert_eq!(assinatura.len(), 256, "assinatura RSA-2048 tem 256 bytes");

    let digest = sha256(canonical(&req.corpo).as_bytes());
    assert!(
        chave.verificar(&digest, &assinatura),
        "o Bearer não é a assinatura da canônica DESTE corpo: {}",
        req.caminho
    );
}

#[test]
fn fluxo_pin_otp_ponta_a_ponta() {
    let amb = Ambiente::novo("pinotp");
    let srv = Servidor::subir(respostas_padrao());
    let motor = motor_preparado(&amb, &srv);

    let digest = sha256(b"conteudo a assinar");
    let fatores = Fatores::PinOtp {
        pin: "1234".into(),
        otp: "999999".into(),
    };
    let assinatura = motor.assinar_digest(&digest, &fatores).unwrap();

    // O motor entrega o bloco CRU, que é o contrato do C_Sign do PKCS#11.
    assert_eq!(assinatura, assinatura_falsa());
    assert_eq!(assinatura.len(), 256);

    // --- o corpo do tokensessao, campo a campo ---
    let tk = srv.requisicao("/tokensessao");
    assert_eq!(tk.corpo["desktopCode"], CODIGO_DESKTOP);
    assert_eq!(tk.corpo["pin"], "1234");
    assert_eq!(tk.corpo["otp"], "999999");
    assert_eq!(tk.corpo["push"], false);
    // Do split do keyName: parte 0 é o serial, parte 1 é o emissor.
    assert_eq!(tk.corpo["serialNumber"], "12CC6B560ECE122AC1047AA7BE71DBC3");
    assert_eq!(tk.corpo["issue"], "CN=AC OAB G3, O=ICP-Brasil, C=BR");
    conferir_bearer(&amb, &tk);

    // --- o corpo do requestHash ---
    let rh = srv.requisicao("/requestHashSessionSignature");
    assert_eq!(rh.corpo["algorithm"], "SHA256");
    assert_eq!(rh.corpo["hashArray"][0]["id"], 0);
    assert!(
        rh.corpo["hashArray"][0]["id"].is_i64(),
        "o id vai como inteiro"
    );
    assert_eq!(rh.corpo["hashArray"][0]["hash"], b64(&digest));
    // O sessionToken é repassado inteiro, sem interpretação.
    assert_eq!(
        rh.corpo["sessionToken"],
        "sessaoAssinatura;327989;CN%3DAC;SER;0;ZXlK;1788393969;hmac="
    );
    conferir_bearer(&amb, &rh);

    // --- a carteira ---
    let ct = srv.requisicao("/carteira");
    assert!(ct.corpo["momento"].is_string(), "momento vai como string");
    conferir_bearer(&amb, &ct);

    // O registro é o único passo, além do login, que usa o JWT.
    let rg = srv.requisicao("/usuario/327989/organizacao/0");
    assert_eq!(rg.autorizacao.as_deref(), Some("Bearer jwt.do.login"));
    assert!(rg.corpo["chavePublica"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(!rg.corpo["dominioRede"].as_str().unwrap().is_empty());
}

#[test]
fn fluxo_push_segue_o_construtor_do_app() {
    let amb = Ambiente::novo("push");
    let srv = Servidor::subir(respostas_padrao());
    let mut motor = motor_preparado(&amb, &srv);
    motor.definir_modo(&Modo::Push);

    let digest = sha256(b"x");
    motor.assinar_digest(&digest, &Fatores::Push).unwrap();

    let tk = srv.requisicao("/tokensessao");
    // Paridade com FUN_100058de6: push=true, pin e otp vazios mas PRESENTES,
    // nomeAplicacaoDesktop preenchido (é o texto que o celular exibe).
    assert_eq!(tk.corpo["push"], true);
    assert_eq!(tk.corpo["pin"], "");
    assert_eq!(tk.corpo["otp"], "");
    assert!(!tk.corpo["nomeAplicacaoDesktop"]
        .as_str()
        .unwrap()
        .is_empty());
    // A assinatura tem de cobrir o corpo COM o push=true, que muda a canônica.
    conferir_bearer(&amb, &tk);
    assert!(canonical(&tk.corpo).contains("push"));
}

#[test]
fn push_com_pin_e_recusado_antes_de_ir_para_a_rede() {
    let amb = Ambiente::novo("misto");
    let srv = Servidor::subir(respostas_padrao());
    let mut motor = motor_preparado(&amb, &srv);
    motor.definir_modo(&Modo::Push);

    // O app oficial não consegue emitir isto: os construtores lançam exceção
    // quando o estado não bate. Falhar aqui é melhor que mandar ao servidor um
    // payload que nenhum cliente oficial produz.
    let erro = motor
        .assinar_digest(
            &sha256(b"x"),
            &Fatores::PinOtp {
                pin: "1234".into(),
                otp: "999999".into(),
            },
        )
        .unwrap_err();
    assert!(
        erro.to_string().contains("push"),
        "erro pouco explicativo: {erro}"
    );

    let houve_tokensessao = srv
        .recebidas
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.caminho.ends_with("/tokensessao"));
    assert!(!houve_tokensessao, "não podia ter ido para a rede");
}

#[test]
fn erro_de_negocio_com_http_200_vira_erro() {
    let amb = Ambiente::novo("informe-pin");
    let mut respostas = respostas_padrao();
    // A resposta literal da run de 02/09/2026 quando o OTP ia vazio.
    respostas.insert(
        "/tokensessao".to_string(),
        json!({"status": false, "message": "Informe o e-Token(Otp)", "token": null}),
    );
    let srv = Servidor::subir(respostas);
    let motor = motor_preparado(&amb, &srv);

    let erro = motor
        .assinar_digest(
            &sha256(b"x"),
            &Fatores::PinOtp {
                pin: "1234".into(),
                otp: "".into(),
            },
        )
        .unwrap_err();
    let texto = erro.to_string();
    assert!(
        texto.contains("Informe o e-Token"),
        "perdeu a mensagem: {texto}"
    );
    // E a dica tem de dizer que o servidor quer os DOIS fatores.
    assert!(texto.contains("pin + otp"), "sem a dica útil: {texto}");
}

#[test]
fn o_log_de_diagnostico_nao_contem_pin_nem_otp() {
    let amb = Ambiente::novo("redacao");
    let srv = Servidor::subir(respostas_padrao());
    let motor = motor_preparado(&amb, &srv);
    motor
        .assinar_digest(
            &sha256(b"x"),
            &Fatores::PinOtp {
                pin: "271828".into(),
                otp: "314159".into(),
            },
        )
        .unwrap();

    let dir = amb.dir.join("diag");
    let mut achou = false;
    for entrada in std::fs::read_dir(&dir).unwrap().flatten() {
        let texto = std::fs::read_to_string(entrada.path()).unwrap();
        if texto.contains("tokensessao") {
            achou = true;
        }
        assert!(
            !texto.contains("271828"),
            "o PIN vazou no log: {}",
            entrada.path().display()
        );
        assert!(!texto.contains("314159"), "o OTP vazou no log");
        // O token de sessão também não sai cru.
        assert!(
            !texto.contains("sessaoAssinatura;327989"),
            "o sessionToken vazou no log"
        );
    }
    assert!(achou, "o log nem registrou o tokensessao");
}
