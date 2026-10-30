//! Grava as fixtures de paridade do protocolo a partir do RemoteID-linux
//! v0.3.2, o código que já conversou com o servidor real da Certisign.
//!
//! O motor antigo roda de verdade, com o transporte HTTP dele, contra um
//! servidor local que grava cada requisição crua (linha, cabeçalhos e corpo em
//! bytes) e devolve uma resposta pronta. O que sai em `tests/paridade/` é o que
//! o antigo mandou e o que ele leu, e os testes do pacote novo comparam 1:1.
//!
//! Todos os valores são sintéticos. Nenhum PIN, OTP, token ou certificado real
//! entra aqui.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use remoteid_aplicacao::{Dependencias, Motor, Opcoes};
use remoteid_autorizacao::Fatores;
use remoteid_cripto::{ChaveInstalacao, b64};
use remoteid_diag_jsonl::Diag;
use remoteid_estado::{Certificado, Estado};
use remoteid_http::Http;
use remoteid_portas::{
    Ambiente, CofreDeChave, Diagnostico, FonteDeCadeia, Relogio, RepositorioEstado,
};
use remoteid_protocolo_servidor::algoritmo::Algoritmo;
use remoteid_protocolo_servidor::config;
use remoteid_tipos::{Error, IdInstalacao, Result};

const CHAVE: &str = include_str!("../../tests/paridade/chave-teste.pem");
const AGORA: u64 = 1_788_393_921;
const CODIGO: &str = "4d1f71d2-c20b-44d0-9bb0-5629015f21e8";
const KEY_NAME: &str = "1A2B3C4D5E6F;CN=AC Teste Sintética G5,OU=Autoridade,O=ICP-Brasil,C=BR";

// --- o servidor que grava -------------------------------------------------

#[derive(Clone, Default)]
struct Servidor {
    respostas: Arc<Mutex<VecDeque<(u16, String)>>>,
    capturadas: Arc<Mutex<Vec<Value>>>,
}

impl Servidor {
    fn subir() -> (Servidor, String) {
        let ouvinte = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", ouvinte.local_addr().unwrap());
        let servidor = Servidor::default();
        let s = servidor.clone();
        std::thread::spawn(move || {
            for conexao in ouvinte.incoming() {
                let mut conexao = conexao.unwrap();
                let capturada = ler_requisicao(&mut BufReader::new(&conexao));
                s.capturadas.lock().unwrap().push(capturada);
                let (status, corpo) = s
                    .respostas
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("requisição sem resposta preparada");
                let cabeca = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    corpo.len()
                );
                conexao.write_all(cabeca.as_bytes()).unwrap();
                conexao.write_all(corpo.as_bytes()).unwrap();
            }
        });
        (servidor, base)
    }

    fn responder(&self, status: u16, corpo: &str) {
        self.respostas
            .lock()
            .unwrap()
            .push_back((status, corpo.to_string()));
    }

    fn tirar(&self) -> Vec<Value> {
        assert!(self.respostas.lock().unwrap().is_empty(), "sobrou resposta");
        std::mem::take(&mut *self.capturadas.lock().unwrap())
    }
}

fn ler_requisicao(leitor: &mut impl BufRead) -> Value {
    let mut linha = String::new();
    leitor.read_line(&mut linha).unwrap();
    let mut partes = linha.trim_end().split(' ');
    let metodo = partes.next().unwrap().to_string();
    let caminho = partes.next().unwrap().to_string();

    let mut cabecalhos = BTreeMap::new();
    loop {
        let mut l = String::new();
        leitor.read_line(&mut l).unwrap();
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        let (nome, valor) = l.split_once(':').unwrap();
        cabecalhos.insert(nome.trim().to_lowercase(), valor.trim().to_string());
    }
    let tamanho: usize = cabecalhos
        .get("content-length")
        .map_or(0, |v| v.parse().unwrap());
    let mut corpo = vec![0; tamanho];
    leitor.read_exact(&mut corpo).unwrap();
    // A porta muda a cada execução e não diz nada do protocolo.
    cabecalhos.remove("host");

    json!({
        "metodo": metodo,
        "caminho": caminho,
        "cabecalhos": cabecalhos,
        "corpo": (tamanho > 0).then(|| String::from_utf8(corpo).unwrap()),
    })
}

// --- as portas do motor antigo ----------------------------------------------

#[derive(Clone, Default)]
struct RepoMem(Arc<Mutex<HashMap<String, Estado>>>);
impl RepositorioEstado for RepoMem {
    fn carregar(&self, id: &IdInstalacao) -> Result<Estado> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(id.como_str())
            .cloned()
            .unwrap_or_else(Estado::novo))
    }
    fn salvar(&self, id: &IdInstalacao, estado: &Estado) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(id.como_str().into(), estado.clone());
        Ok(())
    }
    fn apagar(&self, id: &IdInstalacao) -> Result<()> {
        self.0.lock().unwrap().remove(id.como_str());
        Ok(())
    }
}

struct CofreFixo(ChaveInstalacao);
impl CofreDeChave for CofreFixo {
    fn publica_pem(&self, _: &IdInstalacao) -> Result<String> {
        self.0.publica_pem()
    }
    fn assinar_digest(&self, _: &IdInstalacao, digest: &[u8]) -> Result<Vec<u8>> {
        self.0.assinar_digest(digest)
    }
    fn assinar_pkcs1_v15_cru(&self, _: &IdInstalacao, dados: &[u8]) -> Result<Vec<u8>> {
        self.0.assinar_pkcs1_v15_cru(dados)
    }
    fn bearer_assinado(&self, _: &IdInstalacao, canonical: &str) -> Result<String> {
        self.0.bearer_assinado(canonical)
    }
}

struct SemCadeia;
impl FonteDeCadeia for SemCadeia {
    fn baixar(&self, _: &str) -> Result<Vec<u8>> {
        Err(Error::uso("o gerador não baixa cadeia"))
    }
}

struct RelogioFixo(u64);
impl Relogio for RelogioFixo {
    fn agora(&self) -> u64 {
        self.0
    }
}

struct AmbienteFixo {
    hostname: String,
    usuario: String,
}
impl Ambiente for AmbienteFixo {
    fn hostname(&self) -> String {
        self.hostname.clone()
    }
    fn usuario_local(&self) -> String {
        self.usuario.clone()
    }
}

struct Contexto {
    servidor: Servidor,
    base: String,
}

impl Contexto {
    fn motor_com(&self, agora: u64, hostname: &str, usuario: &str) -> Motor {
        let diag = Arc::new(Diag::inerte()) as Arc<dyn Diagnostico>;
        let opcoes = Opcoes {
            dir_dados: "/nao-existe/paridade".into(),
            dir_diag: "/nao-existe/paridade".into(),
            remoteid_url: self.base.clone(),
            certinext_url: self.base.clone(),
            timeout: Duration::from_secs(5),
            ttl_sessao_hipotetico_s: 900,
        };
        let deps = Dependencias {
            repo: Box::new(RepoMem::default()),
            cofre: Box::new(CofreFixo(ChaveInstalacao::de_pem(CHAVE).unwrap())),
            transporte: Box::new(Http::novo(diag.clone(), Duration::from_secs(5))),
            fonte_cadeia: Box::new(SemCadeia),
            diag,
            relogio: Box::new(RelogioFixo(agora)),
            ambiente: Box::new(AmbienteFixo {
                hostname: hostname.into(),
                usuario: usuario.into(),
            }),
            id: IdInstalacao::local(),
        };
        Motor::com_dependencias(opcoes, deps).unwrap()
    }

    fn motor(&self) -> Motor {
        self.motor_com(AGORA, "host-teste", "usuario-teste")
    }

    /// Um motor já registrado, com `key_name` na carteira.
    fn motor_registrado(&self, key_name: &str) -> Motor {
        let mut m = self.motor();
        m.estado.codigo_desktop = Some(CODIGO.into());
        m.estado.certificados = vec![Certificado::do_key_name(key_name, None).unwrap()];
        m
    }
}

fn uma(capturadas: Vec<Value>) -> Value {
    assert_eq!(
        capturadas.len(),
        1,
        "esperava uma requisição: {capturadas:?}"
    );
    capturadas.into_iter().next().unwrap()
}

// --- requisições ------------------------------------------------------------

fn requisicoes(cx: &Contexto) -> Vec<Value> {
    let mut casos = Vec::new();
    let mut caso = |nome: &str, endpoint: &str, entrada: Value, capturada: Value| {
        casos.push(json!({
            "caso": nome, "endpoint": endpoint, "entrada": entrada, "enviado": capturada,
        }));
    };

    let m = cx.motor();
    cx.servidor.responder(200, "{}");
    m.hierarquias().unwrap();
    caso(
        "hierarquias",
        "hierarquias",
        json!({}),
        uma(cx.servidor.tirar()),
    );

    let credenciais = [
        ("ascii", "titular@exemplo.br", "s3nh4"),
        ("acentos e aspas", "joão.ção@exemplo.br", "sé\"nh'a\\ç"),
        (
            "controle e unicode",
            "a@b.c",
            "lin\nha\ttab\u{1}🔐</script>",
        ),
        ("senha vazia", "titular@exemplo.br", ""),
    ];
    for (nome, email, senha) in credenciais {
        let mut m = cx.motor();
        cx.servidor.responder(200, r#"{"token":"jwt"}"#);
        m.login(email, senha).unwrap();
        caso(
            &format!("login: {nome}"),
            "login",
            json!({"email": email, "senha": senha}),
            uma(cx.servidor.tirar()),
        );
    }

    let registros = [
        (
            "com organização",
            327_989_i64,
            Some(42_i64),
            "meu-pc",
            "host-teste",
            "usuario-teste",
        ),
        (
            "sem organização vira 0",
            1,
            None,
            "meu-pc",
            "host-teste",
            "usuario-teste",
        ),
        (
            "unicode no nome e no ambiente",
            i64::MAX,
            Some(0),
            "Máquina \"da\" Ana",
            "estação-ç",
            "ana.ção",
        ),
    ];
    for (nome, user_id, org, nome_desktop, hostname, usuario) in registros {
        let mut m = cx.motor_com(AGORA, hostname, usuario);
        let mut login = json!({"token": "eyJhbGciOiJIUzI1NiJ9.e30.assinatura", "id": user_id});
        if let Some(org) = org {
            login["organizacaoId"] = json!(org);
        }
        cx.servidor.responder(200, &login.to_string());
        cx.servidor.responder(200, r#"{"codigoDesktop":"x"}"#);
        m.login("a@b.c", "s").unwrap();
        m.registrar(nome_desktop).unwrap();
        let mut capturadas = cx.servidor.tirar();
        let registro = capturadas.pop().unwrap();
        caso(
            &format!("registrar: {nome}"),
            "registrar",
            json!({
                "jwt": "eyJhbGciOiJIUzI1NiJ9.e30.assinatura",
                "user_id": user_id,
                "org_id": org.unwrap_or(0),
                "nome_desktop": nome_desktop,
                "usuario_local": usuario,
                "dominio_rede": hostname,
            }),
            registro,
        );
    }

    for agora in [0, AGORA, u64::MAX] {
        let mut m = cx.motor_com(agora, "h", "u");
        m.estado.codigo_desktop = Some(CODIGO.into());
        cx.servidor
            .responder(200, r#"{"usuarioPossuiCodigoPush":false}"#);
        m.status_celular().unwrap();
        caso(
            &format!("statusCelular: {agora}"),
            "status_celular",
            json!({"codigo_desktop": CODIGO, "agora": agora}),
            uma(cx.servidor.tirar()),
        );

        let mut m = cx.motor_com(agora, "h", "u");
        m.estado.codigo_desktop = Some(CODIGO.into());
        cx.servidor.responder(
            200,
            &json!({"certificados": [{"keyName": KEY_NAME}]}).to_string(),
        );
        m.carteira().unwrap();
        caso(
            &format!("carteira: {agora}"),
            "carteira",
            json!({"codigo_desktop": CODIGO, "agora": agora}),
            uma(cx.servidor.tirar()),
        );
    }

    let sessoes = [
        ("pin e otp numéricos", KEY_NAME, "1234", "999999"),
        ("pin com símbolos", KEY_NAME, "p\"i\\n ç", "000000"),
        ("keyName com vários ;", "SN;CN=AC;OU=a;b", "1234", "123456"),
        ("pin vazio", KEY_NAME, "", "123456"),
    ];
    for (nome, key_name, pin, otp) in sessoes {
        let m = cx.motor_registrado(key_name);
        cx.servidor.responder(200, r#"{"status":true,"token":"T"}"#);
        m.abrir_sessao(&Fatores::PinOtp {
            pin: pin.into(),
            otp: otp.into(),
        })
        .unwrap();
        caso(
            &format!("tokensessao: {nome}"),
            "tokensessao",
            json!({"codigo_desktop": CODIGO, "key_name": key_name, "pin": pin, "otp": otp}),
            uma(cx.servidor.tirar()),
        );
    }

    let token = "sessaoAssinatura;327989;CN=AC;SN;0;ZXlKMGVYQWlPaUpLVjFRaWZRPT0=;1788393921;a1b2c3";
    let blocos: [(&str, Algoritmo, Vec<u8>); 6] = [
        ("SHA256", Algoritmo::Sha256, (0..32).collect()),
        ("cru com 1 byte", Algoritmo::Cru, vec![0xff]),
        ("cru com DigestInfo(MD5)", Algoritmo::Cru, (0..34).collect()),
        (
            "cru com DigestInfo(SHA-256)",
            Algoritmo::Cru,
            (100..151).collect(),
        ),
        (
            "cru no teto de 245",
            Algoritmo::Cru,
            (0..245).map(|i| i as u8).collect(),
        ),
        ("SHA256 com bytes altos", Algoritmo::Sha256, vec![0xfe; 32]),
    ];
    for (nome, algoritmo, dados) in blocos {
        let m = cx.motor_registrado(KEY_NAME);
        cx.servidor.responder(
            200,
            r#"{"status":true,"idArray":[{"id":"0","status":true,"signatureBase64":"AAAA"}]}"#,
        );
        m.assinar_com_sessao(token, algoritmo, &dados).unwrap();
        caso(
            &format!("requestHash: {nome}"),
            "request_hash",
            json!({
                "codigo_desktop": CODIGO,
                "key_name": KEY_NAME,
                "session_token": token,
                "algoritmo": algoritmo.nome(),
                "dados_b64": b64(&dados),
            }),
            uma(cx.servidor.tirar()),
        );
    }

    casos
}

// --- respostas --------------------------------------------------------------

/// O resultado do antigo, na forma que os testes novos comparam.
fn resultado(r: Result<Value>) -> Value {
    match r {
        Ok(v) => json!({"ok": v}),
        Err(Error::Servidor(s)) => json!({"erro": "servidor", "http": s.http_status,
            "mensagem": s.message, "origem": format!("{:?}", s.origem),
            "regra": regra_da_dica(s.hint)}),
        Err(Error::RespostaNaoJson { status, trecho }) => {
            json!({"erro": "nao_json", "http": status, "trecho": trecho})
        }
        Err(Error::Estado(m)) => json!({"erro": "estado", "mensagem": m}),
        Err(Error::Cripto(_)) => json!({"erro": "cripto"}),
        Err(outro) => panic!("erro que o protocolo não produz: {outro}"),
    }
}

/// O fragmento de `SERVER_HINTS` que casou: duas regras podem ter a mesma
/// origem, e só a ordem decide qual vale. Pelo texto da dica, que é único na
/// tabela (o `SERVER_HINTS` é `const`, então o endereço não serve).
fn regra_da_dica(dica: Option<&'static str>) -> Value {
    let dica = match dica {
        Some(d) => d,
        None => return Value::Null,
    };
    let regras: Vec<_> = config::SERVER_HINTS
        .iter()
        .filter(|(_, _, h)| *h == dica)
        .collect();
    assert_eq!(regras.len(), 1, "dica ausente ou repetida: {dica}");
    json!(regras[0].0)
}

fn respostas(cx: &Contexto) -> Vec<Value> {
    let longo = "x".repeat(400);
    let comuns: Vec<(&str, u16, &str)> = vec![
        (
            "200 com status false",
            200,
            r#"{"status":false,"message":"Informe o Pin","token":null}"#,
        ),
        (
            "status como string false",
            200,
            r#"{"status":"false","message":"Informe o e-Token(Otp)"}"#,
        ),
        (
            "status FALSE maiúsculo",
            200,
            r#"{"status":"FALSE","message":"x"}"#,
        ),
        (
            "mensagem em mensagem",
            200,
            r#"{"status":false,"mensagem":"Tempo esgotado"}"#,
        ),
        (
            "mensagem em error",
            200,
            r#"{"status":false,"error":"Service OFFLINE"}"#,
        ),
        (
            "mensagem em exception",
            500,
            r#"{"exception":"UsuarioSenhaInvalidoException"}"#,
        ),
        (
            "message vazia cai em HTTP",
            200,
            r#"{"status":false,"message":""}"#,
        ),
        (
            "message tem prioridade",
            400,
            r#"{"message":"m","mensagem":"n","error":"e"}"#,
        ),
        ("HTTP 401 sem corpo", 401, ""),
        (
            "HTTP 500 com corpo conhecido",
            500,
            r#"{"message":"Internal Server Error"}"#,
        ),
        (
            "HTML do gateway",
            502,
            "<html><body>Bad Gateway</body></html>",
        ),
        ("corpo vazio com 200", 200, ""),
        ("corpo só espaços", 200, "   \n"),
        ("JSON truncado", 200, r#"{"status":tr"#),
        (
            "recusa de fator de campo",
            200,
            r#"{"message":"PIN ou e-Token incorreto","status":false,"token":null}"#,
        ),
        ("corpo longo não-JSON", 503, &longo),
        ("status null passa", 200, r#"{"status":null}"#),
        ("status número passa", 200, r#"{"status":0}"#),
        ("array no topo", 200, "[]"),
    ];

    let especificos: Vec<(&str, &str, u16, String)> = vec![
        ("login", "completo", 200, json!({"token": "jwt.a.b", "id": 327989,
            "organizacaoId": 7, "nome": "Titular Sintético", "cpf": "00000000000"}).to_string()),
        ("login", "sem organização nem nome", 200, r#"{"token":"t","id":1}"#.into()),
        ("login", "id como string", 200, r#"{"token":"t","id":"327989","organizacaoId":"7"}"#.into()),
        ("login", "nome e cpf nulos", 200, r#"{"token":"t","id":1,"nome":null,"cpf":null}"#.into()),
        ("login", "sem token", 200, r#"{"id":1}"#.into()),
        ("login", "token número", 200, r#"{"token":5,"id":1}"#.into()),
        ("login", "token vazio", 200, r#"{"token":"","id":1}"#.into()),
        ("login", "erro de senha", 401, r#"{"message":"Usuário ou senha inválidos"}"#.into()),
        ("registrar", "com código", 200, r#"{"codigoDesktop":"4d1f71d2-c20b"}"#.into()),
        ("registrar", "sem código", 200, r#"{"id":3}"#.into()),
        ("registrar", "código número", 200, r#"{"codigoDesktop":12}"#.into()),
        ("registrar", "constraint", 500, r#"{"message":"could not execute statement; ConstraintViolation"}"#.into()),
        ("status_celular", "true", 200, r#"{"usuarioPossuiCodigoPush":true}"#.into()),
        ("status_celular", "false", 200, r#"{"status":true,"usuarioPossuiCodigoPush":false}"#.into()),
        ("status_celular", "ausente", 200, r#"{"status":true}"#.into()),
        ("status_celular", "string true", 200, r#"{"usuarioPossuiCodigoPush":"true"}"#.into()),
        ("carteira", "dois certificados", 200, json!({"status": true, "certificados": [
            {"keyName": KEY_NAME, "base64": "MIIBsintetico"},
            {"keyName": "FF00;CN=Outra AC", "base64": null}]}).to_string()),
        ("carteira", "item sem keyName é pulado", 200, json!({"certificados": [
            {"base64": "x"}, {"keyName": "A;B"}]}).to_string()),
        ("carteira", "nenhum utilizável", 200, r#"{"certificados":[{"base64":"x"}]}"#.into()),
        ("carteira", "vazia", 200, r#"{"certificados":[]}"#.into()),
        ("carteira", "keyName sem ponto e vírgula", 200, r#"{"certificados":[{"keyName":"semseparador"}]}"#.into()),
        ("carteira", "keyName com vários", 200, r#"{"certificados":[{"keyName":"S;CN=A;OU=b"}]}"#.into()),
        ("carteira", "keyName número", 200, r#"{"certificados":[{"keyName":1},{"keyName":"A;B"}]}"#.into()),
        ("carteira", "certificados não é lista", 200, r#"{"certificados":{}}"#.into()),
        ("carteira", "sem certificados", 200, r#"{"status":true}"#.into()),
        ("carteira", "base64 número", 200, r#"{"certificados":[{"keyName":"A;B","base64":3}]}"#.into()),
        ("tokensessao", "com token", 200, r#"{"status":true,"message":"ok","token":"sessaoAssinatura;1;2"}"#.into()),
        ("tokensessao", "token vazio", 200, r#"{"status":true,"token":""}"#.into()),
        ("tokensessao", "token nulo", 200, r#"{"status":true,"token":null}"#.into()),
        ("tokensessao", "sem token", 200, r#"{"status":true}"#.into()),
        ("tokensessao", "não existe autorização", 200,
            r#"{"status":false,"message":"Não existe autorização válida para este token"}"#.into()),
        ("request_hash", "assinado", 200,
            r#"{"status":true,"idArray":[{"id":"0","status":true,"signatureBase64":"c2luYXR1cmE="}]}"#.into()),
        ("request_hash", "base64 com espaços", 200,
            r#"{"idArray":[{"id":"0","signatureBase64":"  c2luYXR1cmE=\n"}]}"#.into()),
        ("request_hash", "base64 inválido", 200, r#"{"idArray":[{"signatureBase64":"@@@"}]}"#.into()),
        ("request_hash", "item recusado", 200,
            r#"{"status":true,"idArray":[{"id":"0","status":false,"message":"Erro no HSM"}]}"#.into()),
        ("request_hash", "item recusado sem mensagem", 200, r#"{"idArray":[{"status":false}]}"#.into()),
        ("request_hash", "item com status string", 200,
            r#"{"idArray":[{"status":"false","signatureBase64":"AAAA"}]}"#.into()),
        ("request_hash", "sem signatureBase64", 200, r#"{"idArray":[{"status":true}]}"#.into()),
        ("request_hash", "idArray vazio", 200, r#"{"status":true,"idArray":[]}"#.into()),
        ("request_hash", "idArray nulo", 200, r#"{"status":true,"idArray":null}"#.into()),
        ("request_hash", "vários itens usa o primeiro", 200,
            r#"{"idArray":[{"signatureBase64":"AQID"},{"signatureBase64":"BAUG"}]}"#.into()),
        ("request_hash", "recusa do topo com nulos", 200,
            r#"{"certificate":null,"idArray":null,"message":"Erro ao gerar assinatura RSA.","status":false}"#.into()),
    ];

    let endpoints = [
        "login",
        "registrar",
        "status_celular",
        "carteira",
        "tokensessao",
        "request_hash",
    ];
    let mut todos: Vec<(String, &str, u16, String)> = especificos
        .into_iter()
        .map(|(e, n, s, c)| (n.to_string(), e, s, c))
        .collect();
    for endpoint in endpoints {
        for (nome, status, corpo) in &comuns {
            todos.push((nome.to_string(), endpoint, *status, corpo.to_string()));
        }
    }

    todos
        .into_iter()
        .map(|(nome, endpoint, status, corpo)| {
            let esperado = resultado(ler_resposta(cx, endpoint, status, &corpo));
            json!({"caso": nome, "endpoint": endpoint, "http": status, "corpo": corpo,
                "esperado": esperado})
        })
        .collect()
}

/// Faz o motor antigo ler `corpo` como resposta de `endpoint`, e devolve o que
/// ele extraiu.
fn ler_resposta(cx: &Contexto, endpoint: &str, status: u16, corpo: &str) -> Result<Value> {
    let s = &cx.servidor;
    let r = match endpoint {
        "login" => {
            let mut m = cx.motor();
            s.responder(status, corpo);
            match m.login("a@b.c", "s") {
                Err(e) => Err(e),
                Ok(()) => {
                    let mut lido = json!({
                        "id": m.estado.user_id,
                        "organizacao_id": m.estado.organizacao_id,
                        "nome": m.estado.nome,
                        "cpf": m.estado.cpf,
                    });
                    // O JWT fica num campo privado; ele aparece no
                    // Authorization do registro, o único lugar onde o motor o
                    // usa. O registro exige um userId para sair.
                    m.estado.user_id.get_or_insert(1);
                    s.responder(200, r#"{"codigoDesktop":"x"}"#);
                    m.registrar("pc").unwrap();
                    let registro = s.tirar().pop().unwrap();
                    let auth = registro["cabecalhos"]["authorization"].as_str().unwrap();
                    lido["token"] = json!(auth.strip_prefix("Bearer").unwrap().trim_start());
                    Ok(lido)
                }
            }
        }
        "registrar" => {
            let mut m = cx.motor();
            s.responder(200, r#"{"token":"t","id":1}"#);
            m.login("a@b.c", "s").unwrap();
            s.responder(status, corpo);
            m.registrar("pc").map(|c| json!({"codigo_desktop": c}))
        }
        "status_celular" => {
            let mut m = cx.motor_registrado(KEY_NAME);
            s.responder(status, corpo);
            m.status_celular()
                .map(|b| json!({"usuario_possui_codigo_push": b}))
        }
        "carteira" => {
            let mut m = cx.motor_registrado(KEY_NAME);
            s.responder(status, corpo);
            m.carteira().map(|certs| {
                json!({"certificados": certs.iter().map(|c| json!({
                    "key_name": c.key_name, "serial_number": c.serial_number,
                    "issue": c.issue, "base64": c.base64,
                })).collect::<Vec<_>>()})
            })
        }
        "tokensessao" => {
            let m = cx.motor_registrado(KEY_NAME);
            s.responder(status, corpo);
            m.abrir_sessao(&Fatores::PinOtp {
                pin: "1".into(),
                otp: "2".into(),
            })
            .map(|t| json!({"token": t}))
        }
        "request_hash" => {
            let m = cx.motor_registrado(KEY_NAME);
            s.responder(status, corpo);
            m.assinar_com_sessao("T", Algoritmo::Sha256, &[0; 32])
                .map(|a| json!({"assinatura_b64": b64(&a)}))
        }
        outro => panic!("endpoint desconhecido: {outro}"),
    };
    // Esvazia as capturas deste caso.
    s.tirar();
    r
}

// --- classificação, algoritmo e constantes ------------------------------------

fn classificacao() -> Vec<Value> {
    let mut mensagens: Vec<(String, String)> = config::SERVER_HINTS
        .iter()
        .flat_map(|(f, _, _)| {
            [
                (f.to_string(), String::new()),
                (f.to_uppercase(), String::new()),
                (
                    String::new(),
                    format!(r#"{{"detalhe":"antes {f} depois"}}"#),
                ),
            ]
        })
        .collect();
    for (m, c) in [
        ("PIN ou e-Token incorreto", ""),
        ("Informe o e-Token(Otp)", ""),
        ("Não existe autorização válida para este token", ""),
        ("Token expirado", ""),
        ("Sessão inválida", ""),
        ("session timeout", ""),
        ("Erro ao gerar assinatura RSA.", ""),
        (
            "Erro ao gerar assinatura RSA.Invalid input data size.(1011)",
            "",
        ),
        ("Error sending apns server", ""),
        ("bloop", ""),
        ("", ""),
        ("Senha inválida", r#"{"session":"x"}"#),
        ("ÁÉÍ não existe autorização válida", ""),
        ("NÃO EXISTE AUTORIZAÇÃO VÁLIDA", ""),
        ("token inválido", ""),
        ("HTTP 500", "<html>Internal Server Error</html>"),
    ] {
        mensagens.push((m.into(), c.into()));
    }
    mensagens
        .into_iter()
        .map(|(mensagem, corpo)| {
            let (origem, dica) = config::classificar(&mensagem, &corpo);
            json!({
                "mensagem": mensagem, "corpo": corpo,
                "origem": format!("{origem:?}"), "regra": regra_da_dica(dica),
                "falha_de_sessao": config::e_falha_de_sessao(&mensagem, &corpo),
            })
        })
        .collect()
}

fn algoritmo() -> Vec<Value> {
    let mut casos = Vec::new();
    for a in [Algoritmo::Sha256, Algoritmo::Cru] {
        for tamanho in [0, 1, 20, 31, 32, 33, 34, 51, 244, 245, 246, 255, 256, 512] {
            casos.push(json!({
                "algoritmo": a.nome(), "tamanho": tamanho,
                "aceito": a.validar(&vec![7; tamanho]).is_ok(),
            }));
        }
    }
    for nome in ["SHA256", "", "SHA1", "MD5", "sha256", " SHA256"] {
        casos.push(json!({"nome": nome, "conhecido": Algoritmo::do_nome(nome).is_some()}));
    }
    casos
}

/// A canônica direto, para as regras que nenhum corpo do caminho PIN+OTP
/// exercita (o `push` vai sempre `false` lá).
fn canonica() -> Vec<Value> {
    let corpos = [
        json!({"push": true}),
        json!({"push": false, "pin": "", "otp": null}),
        json!({"z": "Z", "a": "A", "m": "M"}),
        json!({"desktopCode": "DC", "pin": "", "otp": "", "push": true,
            "nomeAplicacaoDesktop": "RemoteID-linux", "issue": "CN=AC", "serialNumber": "SN"}),
        json!({"lista": [true, false, null, "s", 1, {"interno": true}]}),
        json!({"n": 0, "negativo": -42, "grande": i64::MAX, "maior": u64::MAX, "real": 1.5}),
        json!({"Z": "maiúscula", "a": "minúscula", "_": "sublinhado", "1": "número"}),
        json!({"ç": "cedilha", "é": "acento", "e": "sem"}),
        json!({"aninhado": {"b": {"c": true, "a": "x"}, "a": [[["fundo"]]]}}),
        json!(["topo", true, {"k": true}]),
        json!("só uma string"),
        json!(null),
        json!({"vazio": {}, "lista_vazia": [], "texto": "\"aspas\" \\ \n"}),
    ];
    let chave = ChaveInstalacao::de_pem(CHAVE).unwrap();
    corpos
        .into_iter()
        .map(|corpo| {
            let c = remoteid_protocolo_servidor::canonical::canonical(&corpo);
            json!({"corpo": corpo, "canonica": c, "bearer": chave.bearer_assinado(&c).unwrap()})
        })
        .collect()
}

fn constantes() -> Value {
    json!({
        "remoteid_url": config::REMOTEID_URL,
        "certinext_url": config::CERTINEXT_URL,
        "certinext_base": config::CERTINEXT_BASE,
        "user_agent": config::USER_AGENT,
        "nome_aplicacao": config::NOME_APLICACAO,
        "algoritmo_padrao": Algoritmo::default().nome(),
    })
}

fn gravar(destino: &Path, nome: &str, valor: &Value) {
    let texto = serde_json::to_string_pretty(valor).unwrap() + "\n";
    std::fs::write(destino.join(nome), texto).unwrap();
    println!("{nome}");
}

fn main() {
    let (servidor, base) = Servidor::subir();
    let cx = Contexto { servidor, base };
    let destino = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/paridade");

    let reqs = requisicoes(&cx);
    let resps = respostas(&cx);
    // Um gerador que não gera nada passaria qualquer teste.
    assert!(
        reqs.len() >= 20 && resps.len() >= 100,
        "{} {}",
        reqs.len(),
        resps.len()
    );

    gravar(&destino, "requisicoes.json", &Value::Array(reqs));
    gravar(&destino, "respostas.json", &Value::Array(resps));
    gravar(
        &destino,
        "classificacao.json",
        &Value::Array(classificacao()),
    );
    gravar(&destino, "algoritmo.json", &Value::Array(algoritmo()));
    gravar(&destino, "canonica.json", &Value::Array(canonica()));
    gravar(&destino, "constantes.json", &constantes());
}
