//! Fluxo otimista do daemon contra um servidor RemoteID enlatado.
//!
//! Prova três coisas que a decisão de "cache do sessionToken por certificado
//! + retry silencioso" (03/09/2026) exige:
//!
//! 1. Sem cache, o daemon pede fatores ao prompter, emite `tokensessao`,
//!    assina, e GRAVA o token no state.
//! 2. Com cache válido, o daemon assina SEM chamar o prompter e SEM tocar
//!    no `tokensessao`.
//! 3. Se o servidor rejeitar o cache como "sessão inválida", o daemon
//!    INVALIDA a entrada, chama o prompter, reemite o token, e assina — o
//!    módulo/hospedeiro vê APENAS a assinatura, nada de "sessão expirada".
//!
//! O servidor de teste é o mesmo padrão do
//! `remoteid-aplicacao/tests/fluxo.rs`: TCP local, respostas enlatadas por path.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use remoteid_aplicacao::{Motor, Opcoes};
use remoteid_autorizacao::Fatores;
use remoteid_cripto::{b64, de_b64};
use serde_json::{json, Value};

use remoteid_daemon::prompter::{Contexto, Prompter};
use remoteid_daemon::protocolo::{CodigoErro, Requisicao, Resposta, SucessoResposta};
use remoteid_daemon::servico::Servico;

// ---------------- servidor HTTP local, com controle de "modo" -----------

#[derive(Debug, Clone)]
struct ReqHttp {
    caminho: String,
    #[allow(dead_code)]
    corpo: Value,
}

/// Comportamento do endpoint `requestHashSessionSignature`. Muda em runtime
/// por `set_modo_request_hash` para exercitar o retry silencioso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModoReq {
    /// Devolve assinatura válida.
    Ok,
    /// Devolve `{"status":false, "message":"Não existe autorização válida para este token"}`,
    /// como o servidor faria com um `sessionToken` já vencido.
    SessaoInvalida,
}

struct Servidor {
    base: String,
    recebidas: Arc<Mutex<Vec<ReqHttp>>>,
    /// Comportamentos programados para as próximas chamadas de
    /// `requestHashSessionSignature`. Uma queue: cada chamada consome um
    /// elemento; quando esvazia, cai para `ModoReq::Ok`. Isso evita a
    /// corrida que uma flag global teria (o retry silencioso emite
    /// tokensessao e depois chama request_hash de novo, quase sem gap).
    modos_reqhash: Arc<Mutex<std::collections::VecDeque<ModoReq>>>,
    contador_tokensessao: Arc<Mutex<u32>>,
    contador_reqhash: Arc<Mutex<u32>>,
}

impl Servidor {
    fn subir() -> Servidor {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let porta = listener.local_addr().unwrap().port();
        let recebidas = Arc::new(Mutex::new(Vec::new()));
        let modos = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let contador_ts = Arc::new(Mutex::new(0u32));
        let contador_rh = Arc::new(Mutex::new(0u32));

        let recebidas_c = Arc::clone(&recebidas);
        let modos_c = Arc::clone(&modos);
        let ts_c = Arc::clone(&contador_ts);
        let rh_c = Arc::clone(&contador_rh);
        std::thread::spawn(move || {
            for fluxo in listener.incoming() {
                let Ok(fluxo) = fluxo else { continue };
                let _ = atender(fluxo, &recebidas_c, &modos_c, &ts_c, &rh_c);
            }
        });
        Servidor {
            base: format!("http://127.0.0.1:{porta}"),
            recebidas,
            modos_reqhash: modos,
            contador_tokensessao: contador_ts,
            contador_reqhash: contador_rh,
        }
    }

    /// Programa que a PRÓXIMA request_hash devolva `m`. Se chamada várias
    /// vezes, empilha em ordem. Depois de esgotada, o servidor volta a OK.
    fn programar_request_hash(&self, m: ModoReq) {
        self.modos_reqhash.lock().unwrap().push_back(m);
    }

    fn contagem_de_tokensessao(&self) -> u32 {
        *self.contador_tokensessao.lock().unwrap()
    }

    #[allow(dead_code)]
    fn contagem_de_reqhash(&self) -> u32 {
        *self.contador_reqhash.lock().unwrap()
    }

    #[allow(dead_code)]
    fn recebidos_para(&self, sufixo: &str) -> Vec<ReqHttp> {
        self.recebidas
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.caminho.ends_with(sufixo))
            .cloned()
            .collect()
    }
}

fn atender(
    mut fluxo: TcpStream,
    recebidas: &Arc<Mutex<Vec<ReqHttp>>>,
    modos_reqhash: &Arc<Mutex<std::collections::VecDeque<ModoReq>>>,
    contador_ts: &Arc<Mutex<u32>>,
    contador_rh: &Arc<Mutex<u32>>,
) -> std::io::Result<()> {
    let mut leitor = BufReader::new(fluxo.try_clone()?);
    let mut linha = String::new();
    leitor.read_line(&mut linha)?;
    let caminho = linha.split_whitespace().nth(1).unwrap_or("/").to_string();

    let mut tamanho = 0usize;
    loop {
        let mut h = String::new();
        if leitor.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some(v) = h.to_lowercase().strip_prefix("content-length:") {
            tamanho = v.trim().parse().unwrap_or(0);
        }
    }
    let mut buf = vec![0u8; tamanho];
    if tamanho > 0 {
        leitor.read_exact(&mut buf)?;
    }
    let corpo: Value = serde_json::from_slice(&buf).unwrap_or(Value::Null);
    recebidas.lock().unwrap().push(ReqHttp {
        caminho: caminho.clone(),
        corpo,
    });

    let resposta = if caminho.ends_with("/login/usrsenha") {
        json!({
            "status": true, "message": "ok",
            "token": "eyJraWQiOiJ0ZXN0In0.eyJzdWIiOiIxIn0.abc",
            "id": 327989, "organizacaoId": 100, "nome": "Titular Teste", "cpf": "00000000000"
        })
    } else if caminho.contains("/desktopid/usuario/") {
        json!({"status": true, "message": "ok", "codigoDesktop": "cd-uuid"})
    } else if caminho.ends_with("/carteira") {
        json!({
            "status": true, "message": "ok",
            "certificados": [{
                "keyName": "12CC6B56;CN=AC OAB G3, O=ICP-Brasil, C=BR",
                "base64": b64(&[0u8; 4])
            }]
        })
    } else if caminho.ends_with("/statusCelular") {
        json!({"status": true, "usuarioPossuiCodigoPush": false})
    } else if caminho.ends_with("/tokensessao") {
        *contador_ts.lock().unwrap() += 1;
        // Epoch bem no presente para o pré-filtro deixar passar. Cada
        // emissão nasce com um epoch levemente maior para diferenciar
        // tokens (senão o `visto_em` do cache seria o mesmo entre
        // primeira e segunda emissão, e o teste do `cache_hit` ficaria
        // ambíguo).
        let ep = agora_test() + 60 + *contador_ts.lock().unwrap() as u64;
        let token = format!("sessaoAssinatura;327989;CN%3DAC;12CC6B56;0;jwt;{ep};hmac");
        json!({"status": true, "message": "Token gerado com sucesso", "token": token})
    } else if caminho.ends_with("/requestHashSessionSignature") {
        *contador_rh.lock().unwrap() += 1;
        let modo = modos_reqhash
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(ModoReq::Ok);
        match modo {
            ModoReq::Ok => json!({
                "status": true, "message": "ok",
                "idArray": [{"id": "0", "status": true, "message": "ok",
                             "signatureBase64": b64(&assinatura_falsa())}]
            }),
            ModoReq::SessaoInvalida => json!({
                "status": false,
                "message": "Não existe autorização válida para este token"
            }),
        }
    } else {
        json!({"status": false, "message": "endpoint desconhecido"})
    };

    let body = serde_json::to_string(&resposta).unwrap();
    write!(
        fluxo,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )?;
    fluxo.flush()?;
    Ok(())
}

fn assinatura_falsa() -> Vec<u8> {
    // 256 bytes: o motor confere o tamanho.
    vec![0xAB; 256]
}

fn agora_test() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------- prompter que conta chamadas ----------------------------

struct PrompterEspiao {
    pin: String,
    otp: String,
    chamadas: Mutex<u32>,
}

impl PrompterEspiao {
    fn novo() -> Arc<Self> {
        Arc::new(PrompterEspiao {
            pin: "1234".into(),
            otp: "999999".into(),
            chamadas: Mutex::new(0),
        })
    }
    fn contagem(&self) -> u32 {
        *self.chamadas.lock().unwrap()
    }
}

impl Prompter for PrompterEspiao {
    fn pedir_pin_otp(&self, _: &Contexto) -> remoteid_tipos::Result<Fatores> {
        *self.chamadas.lock().unwrap() += 1;
        Ok(Fatores::PinOtp {
            pin: self.pin.clone(),
            otp: self.otp.clone(),
        })
    }
}

// Wrapper para o Servico aceitar o Arc<PrompterEspiao> como Box<dyn>.
struct ProxyPrompter(Arc<PrompterEspiao>);
impl Prompter for ProxyPrompter {
    fn pedir_pin_otp(&self, c: &Contexto) -> remoteid_tipos::Result<Fatores> {
        self.0.pedir_pin_otp(c)
    }
}

// ---------------- ambiente com dir temporário ---------------------------

struct Ambiente {
    dir: std::path::PathBuf,
}

impl Ambiente {
    fn novo(nome: &str) -> Ambiente {
        let dir = std::env::temp_dir().join(format!("dtid-daemon-{nome}-{}", std::process::id()));
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

fn preparar_motor(amb: &Ambiente, srv: &Servidor) {
    let mut motor = Motor::abrir(amb.opcoes(&srv.base)).unwrap();
    motor.login("teste@exemplo.br", "senha").unwrap();
    motor.registrar("maquina-teste").unwrap();
    motor.carteira().unwrap();
    motor.salvar_estado().unwrap();
}

fn servico(amb: &Ambiente, srv: &Servidor, prompter: Arc<PrompterEspiao>) -> Servico {
    Servico::novo(amb.opcoes(&srv.base), Box::new(ProxyPrompter(prompter))).unwrap()
}

// ---------------- os testes ---------------------------------------------

#[test]
fn primeira_assinatura_sem_cache_pede_pin_otp_e_grava_a_sessao() {
    let amb = Ambiente::novo("primeira");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    let req = Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[0u8; 32]),
        hospedeiro: Some("papers".into()),
    };
    let resp = s.tratar(req);

    match resp {
        Resposta::Sucesso(SucessoResposta::Sign { cache_hit, .. }) => {
            assert!(!cache_hit, "primeira assinatura NÃO é cache hit");
        }
        outro => panic!("resposta inesperada: {outro:?}"),
    }
    assert_eq!(prompter.contagem(), 1, "pediu PIN+OTP uma vez");
    assert_eq!(
        srv.contagem_de_tokensessao(),
        1,
        "chamou tokensessao uma vez"
    );
}

#[test]
fn segunda_assinatura_com_cache_valido_nao_pede_pin_otp_nem_toca_tokensessao() {
    let amb = Ambiente::novo("cache_hit");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    // primeira: gasta OTP.
    s.tratar(Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[0u8; 32]),
        hospedeiro: None,
    });
    // segunda: deve reusar.
    let resp = s.tratar(Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[1u8; 32]),
        hospedeiro: None,
    });

    match resp {
        Resposta::Sucesso(SucessoResposta::Sign { cache_hit, .. }) => {
            assert!(cache_hit, "segunda assinatura DEVE ser cache hit");
        }
        outro => panic!("resposta inesperada: {outro:?}"),
    }
    assert_eq!(
        prompter.contagem(),
        1,
        "prompter só foi chamado uma vez (a primeira)"
    );
    assert_eq!(
        srv.contagem_de_tokensessao(),
        1,
        "tokensessao só foi chamado uma vez"
    );
}

#[test]
fn cache_recusado_pelo_server_invalida_e_reemite_transparente() {
    let amb = Ambiente::novo("retry");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    // Primeira assinatura: emite token normalmente (server OK) e cacheia.
    s.tratar(Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[0u8; 32]),
        hospedeiro: None,
    });
    assert_eq!(prompter.contagem(), 1);
    assert_eq!(srv.contagem_de_tokensessao(), 1);

    // Programa: a PRÓXIMA request_hash recusa (sessão inválida), e a de
    // depois é OK (a reemissão após o retry). Sem race — a queue garante
    // ordem determinística mesmo em CI apertado.
    srv.programar_request_hash(ModoReq::SessaoInvalida);
    srv.programar_request_hash(ModoReq::Ok);

    let resp = s.tratar(Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[2u8; 32]),
        hospedeiro: None,
    });

    match resp {
        Resposta::Sucesso(SucessoResposta::Sign { cache_hit, .. }) => {
            // Não foi hit puro: hit → invalidação → reemissão nova.
            assert!(!cache_hit, "após retry, cache_hit deve ser false");
        }
        outro => panic!("resposta inesperada, deveria ter feito retry silencioso: {outro:?}"),
    }
    assert_eq!(
        prompter.contagem(),
        2,
        "prompter chamado no retry silencioso"
    );
    assert_eq!(
        srv.contagem_de_tokensessao(),
        2,
        "reemitiu o tokensessao no retry"
    );
    assert_eq!(
        srv.contagem_de_reqhash(),
        3,
        "1 primeiro + 1 recusa + 1 retry OK"
    );
}

#[test]
fn reautorizar_proxima_forca_pin_otp_na_proxima() {
    let amb = Ambiente::novo("reautorizar");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    // Cria cache.
    s.tratar(Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[0u8; 32]),
        hospedeiro: None,
    });
    // Reset leve.
    let ack = s.tratar(Requisicao::ReautorizarProxima);
    assert!(matches!(
        ack,
        Resposta::Sucesso(SucessoResposta::Ack { .. })
    ));
    // Próxima assinatura precisa pedir de novo.
    s.tratar(Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[1u8; 32]),
        hospedeiro: None,
    });

    assert_eq!(
        prompter.contagem(),
        2,
        "reautorizar forçou o segundo PIN+OTP"
    );
    assert_eq!(srv.contagem_de_tokensessao(), 2);
}

#[test]
fn digest_com_tamanho_errado_devolve_entrada_invalida_nao_erro_interno() {
    let amb = Ambiente::novo("digest_ruim");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    let req = Requisicao::Sign {
        algoritmo: None,
        digest_b64: b64(&[0u8; 20]),
        hospedeiro: None,
    };
    match s.tratar(req) {
        Resposta::Falha { codigo, .. } => assert_eq!(codigo, CodigoErro::EntradaInvalida),
        outro => panic!("digest inválido não pode virar sucesso: {outro:?}"),
    }
    // E não gastou OTP nem chamou o servidor.
    assert_eq!(prompter.contagem(), 0);
    assert_eq!(srv.contagem_de_tokensessao(), 0);
    // usa o b64 pra silenciar warning no import
    let _ = de_b64(&b64(&[0u8; 32]));
}

#[test]
fn modo_cru_manda_o_bloco_inteiro_com_algorithm_vazio() {
    // O caminho do PJeOffice: o módulo recebe o DigestInfo(MD5) pronto no
    // CKM_RSA_PKCS (34 bytes) e pede ao daemon o modo cru. O que tem de
    // chegar ao servidor é o bloco INTEIRO, com `algorithm` presente e vazio,
    // que foi o corpo que a sondagem de 05/09/2026 provou funcionar.
    let amb = Ambiente::novo("cru");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    let bloco: Vec<u8> = (0..34u8).collect();
    let resp = s.tratar(Requisicao::Sign {
        algoritmo: Some(String::new()),
        digest_b64: b64(&bloco),
        hospedeiro: Some("java".into()),
    });
    match resp {
        Resposta::Sucesso(SucessoResposta::Sign { assinatura_b64, .. }) => {
            assert_eq!(de_b64(&assinatura_b64).unwrap().len(), 256);
        }
        outro => panic!("resposta inesperada: {outro:?}"),
    }
    let recebidas = srv.recebidos_para("/requestHashSessionSignature");
    assert_eq!(recebidas.len(), 1);
    let corpo = &recebidas[0].corpo;
    assert_eq!(corpo["algorithm"], "", "o campo vai presente e vazio");
    assert_eq!(corpo["hashArray"][0]["hash"], b64(&bloco));
    assert_eq!(prompter.contagem(), 1);

    // A mesma sessão serve o outro modo em seguida, sem PIN de novo: os dois
    // modos compartilham o cache (a sondagem fez cinco casos numa sessão só).
    match s.tratar(Requisicao::Sign {
        algoritmo: Some("SHA256".into()),
        digest_b64: b64(&[7u8; 32]),
        hospedeiro: None,
    }) {
        Resposta::Sucesso(SucessoResposta::Sign { cache_hit, .. }) => assert!(cache_hit),
        outro => panic!("resposta inesperada: {outro:?}"),
    }
    assert_eq!(prompter.contagem(), 1, "não pediu PIN+OTP de novo");
    assert_eq!(srv.contagem_de_tokensessao(), 1);
}

#[test]
fn algoritmo_desconhecido_ou_bloco_fora_do_teto_nao_gastam_otp() {
    let amb = Ambiente::novo("cru_ruim");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let prompter = PrompterEspiao::novo();
    let mut s = servico(&amb, &srv, Arc::clone(&prompter));

    // O servidor até honra SHA1 por nome, mas este cliente só fala os dois
    // modos do domínio: o resto é entrada inválida, sem chute.
    let casos: Vec<(Option<String>, Vec<u8>)> = vec![
        (Some("SHA1".into()), vec![0u8; 20]),
        (Some("MD5".into()), vec![0u8; 16]),
        (Some(String::new()), vec![0u8; 246]),
        (Some(String::new()), vec![]),
        (Some("SHA256".into()), vec![0u8; 34]),
    ];
    for (algoritmo, dados) in casos {
        let rotulo = format!("{algoritmo:?} com {} bytes", dados.len());
        match s.tratar(Requisicao::Sign {
            algoritmo,
            digest_b64: b64(&dados),
            hospedeiro: None,
        }) {
            Resposta::Falha { codigo, .. } => {
                assert_eq!(codigo, CodigoErro::EntradaInvalida, "{rotulo}")
            }
            outro => panic!("{rotulo} não pode virar sucesso: {outro:?}"),
        }
    }
    assert_eq!(prompter.contagem(), 0, "nenhum caso pediu PIN+OTP");
    assert_eq!(srv.contagem_de_tokensessao(), 0);
    assert_eq!(srv.contagem_de_reqhash(), 0);
}

#[test]
fn status_espelha_o_estado() {
    let amb = Ambiente::novo("status");
    let srv = Servidor::subir();
    preparar_motor(&amb, &srv);

    let mut s = servico(&amb, &srv, PrompterEspiao::novo());
    match s.tratar(Requisicao::Status) {
        Resposta::Sucesso(SucessoResposta::Status {
            preparado,
            codigo_desktop,
            certificados,
            ..
        }) => {
            assert!(preparado);
            assert_eq!(codigo_desktop.as_deref(), Some("cd-uuid"));
            assert_eq!(certificados.len(), 1);
        }
        outro => panic!("status errado: {outro:?}"),
    }
}
