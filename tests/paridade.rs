//! Paridade 1:1 com o RemoteID-linux v0.3.2 no protocolo com a Certisign.
//!
//! As fixtures em `tests/paridade/` foram gravadas pelo `paridade/`, rodando o
//! código antigo de verdade: o que ele mandou (método, URL, cabeçalhos e corpo
//! em bytes, com o `Bearer` assinado pela mesma chave de teste) e o que ele leu
//! de cada resposta. Aqui o código novo recebe as mesmas entradas e tem de dar
//! o mesmo resultado. Cada teste junta todas as diferenças antes de falhar.

use serde_json::{Value, json};

use remoteid::cripto::{ChaveInstalacao, b64, de_b64};
use remoteid::protocolo::canonica::canonica;
use remoteid::protocolo::classificacao::{self, Origem, Regra};
use remoteid::protocolo::requisicao::{self, Maquina};
use remoteid::protocolo::resposta::{self, Erro};
use remoteid::protocolo::{self as p, Algoritmo, Certificado, Requisicao, Servidor};

fn fixture(nome: &str, minimo: usize) -> Vec<Value> {
    let caminho = format!("{}/tests/paridade/{nome}", env!("CARGO_MANIFEST_DIR"));
    let texto = std::fs::read_to_string(&caminho).expect(&caminho);
    let casos: Vec<Value> = serde_json::from_str(&texto).unwrap();
    // Uma fixture vazia ou truncada passaria em todos os testes.
    assert!(casos.len() >= minimo, "{nome}: só {} casos", casos.len());
    casos
}

fn chave() -> ChaveInstalacao {
    ChaveInstalacao::de_pem(include_str!("paridade/chave-teste.pem")).unwrap()
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} em {v}"))
        .to_string()
}

fn conferir(diferencas: Vec<String>) {
    assert!(
        diferencas.is_empty(),
        "{} diferença(s) com o RemoteID-linux:\n\n{}",
        diferencas.len(),
        diferencas.join("\n\n")
    );
}

// --- requisições ------------------------------------------------------------

fn montar(srv: &Servidor, endpoint: &str, e: &Value, chave: &ChaveInstalacao) -> Requisicao {
    let cert = || Certificado::do_key_name(&s(e, "key_name"), None).unwrap();
    match endpoint {
        "hierarquias" => requisicao::hierarquias(srv),
        "login" => requisicao::login(srv, &s(e, "email"), &s(e, "senha")),
        "registrar" => requisicao::registrar(
            srv,
            &s(e, "jwt"),
            e["user_id"].as_i64().unwrap(),
            e["org_id"].as_i64().unwrap(),
            &Maquina {
                nome: &s(e, "nome_desktop"),
                usuario_local: &s(e, "usuario_local"),
                dominio_rede: &s(e, "dominio_rede"),
            },
            chave,
        ),
        "status_celular" => requisicao::status_celular(
            srv,
            &s(e, "codigo_desktop"),
            e["agora"].as_u64().unwrap(),
            chave,
        ),
        "carteira" => requisicao::carteira(
            srv,
            &s(e, "codigo_desktop"),
            e["agora"].as_u64().unwrap(),
            chave,
        ),
        "tokensessao" => requisicao::tokensessao(
            srv,
            &s(e, "codigo_desktop"),
            &cert(),
            &s(e, "pin"),
            &s(e, "otp"),
            chave,
        ),
        "request_hash" => requisicao::request_hash(
            srv,
            &s(e, "codigo_desktop"),
            &s(e, "session_token"),
            &cert(),
            Algoritmo::do_nome(&s(e, "algoritmo")).unwrap(),
            &de_b64(&s(e, "dados_b64")).unwrap(),
            chave,
        ),
        outro => panic!("endpoint desconhecido: {outro}"),
    }
}

/// O que o transporte acrescenta e o protocolo não define.
const DO_TRANSPORTE: [&str; 2] = ["accept-encoding", "content-length"];

#[test]
fn as_requisicoes_saem_iguais_byte_a_byte() {
    let chave = chave();
    let mut diferencas = Vec::new();
    for caso in fixture("requisicoes.json", 24) {
        let nova = montar(
            &Servidor::producao(),
            &s(&caso, "endpoint"),
            &caso["entrada"],
            &chave,
        );
        let antiga = &caso["enviado"];
        let base = if caso["endpoint"] == "hierarquias" {
            p::CERTINEXT_URL
        } else {
            p::REMOTEID_URL
        };

        let mut cabecalhos: serde_json::Map<String, Value> =
            antiga["cabecalhos"].as_object().unwrap().clone();
        cabecalhos.retain(|k, _| !DO_TRANSPORTE.contains(&k.as_str()));
        let novos: serde_json::Map<String, Value> = nova
            .cabecalhos()
            .into_iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();

        let comparacoes = [
            (
                "método",
                json!(nova.metodo.nome()),
                antiga["metodo"].clone(),
            ),
            (
                "URL",
                json!(nova.url),
                json!(format!("{base}{}", s(antiga, "caminho"))),
            ),
            ("corpo", json!(nova.corpo), antiga["corpo"].clone()),
            (
                "cabeçalhos",
                Value::Object(novos),
                Value::Object(cabecalhos),
            ),
        ];
        for (o_que, novo, antigo) in comparacoes {
            if novo != antigo {
                diferencas.push(format!(
                    "{}: {o_que}\n  novo:   {novo}\n  antigo: {antigo}",
                    s(&caso, "caso")
                ));
            }
        }
    }
    conferir(diferencas);
}

/// Um servidor local que grava a requisição crua, como o do gerador, e
/// responde `{}`.
fn gravador() -> (String, std::sync::mpsc::Receiver<Value>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let ouvinte = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", ouvinte.local_addr().unwrap());
    let (envia, recebe) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for conexao in ouvinte.incoming() {
            let mut conexao = conexao.unwrap();
            let mut leitor = BufReader::new(&conexao);
            let mut linha = String::new();
            leitor.read_line(&mut linha).unwrap();
            let mut partes = linha.split_whitespace();
            let (metodo, caminho) = (partes.next().unwrap(), partes.next().unwrap());
            let mut cabecalhos = serde_json::Map::new();
            loop {
                let mut l = String::new();
                leitor.read_line(&mut l).unwrap();
                let Some((nome, valor)) = l.trim_end().split_once(':') else {
                    break;
                };
                cabecalhos.insert(nome.trim().to_lowercase(), json!(valor.trim()));
            }
            let tamanho = cabecalhos
                .get("content-length")
                .map_or(0, |v| v.as_str().unwrap().parse().unwrap());
            let mut corpo = vec![0; tamanho];
            leitor.read_exact(&mut corpo).unwrap();
            cabecalhos.remove("host");
            let capturada = json!({"metodo": metodo, "caminho": caminho,
                "cabecalhos": cabecalhos,
                "corpo": (tamanho > 0).then(|| String::from_utf8(corpo).unwrap())});
            conexao
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
            envia.send(capturada).unwrap();
        }
    });
    (base, recebe)
}

#[test]
fn o_transporte_manda_os_mesmos_bytes_e_cabecalhos() {
    use remoteid::transporte::{Http, TEMPO_LIMITE, Transporte};
    let chave = chave();
    let (base, capturadas) = gravador();
    let servidor = Servidor::falso(&base);
    let http = Http::novo(TEMPO_LIMITE);
    let mut diferencas = Vec::new();
    for caso in fixture("requisicoes.json", 24) {
        let requisicao = montar(&servidor, &s(&caso, "endpoint"), &caso["entrada"], &chave);
        let resposta = http.enviar(&requisicao).unwrap();
        assert_eq!((resposta.http, resposta.corpo.as_str()), (200, "{}"));
        let enviada = capturadas.recv().unwrap();
        if enviada != caso["enviado"] {
            diferencas.push(format!(
                "{}\n  novo:   {enviada}\n  antigo: {}",
                s(&caso, "caso"),
                caso["enviado"]
            ));
        }
    }
    conferir(diferencas);
}

// --- respostas --------------------------------------------------------------

fn regra(r: Option<&'static Regra>) -> Value {
    json!(r.map(|r| r.fragmento))
}

fn origem(r: Option<&'static Regra>) -> String {
    format!("{:?}", r.map_or(Origem::Desconhecida, |r| r.origem))
}

/// O resultado novo na forma da fixture.
fn lido<T>(r: Result<T, Erro>, ok: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => json!({"ok": ok(v)}),
        Err(Erro::Servidor {
            http,
            mensagem,
            regra: r,
        }) => json!({"erro": "servidor", "http": http, "mensagem": mensagem,
            "origem": origem(r), "regra": regra(r)}),
        Err(Erro::NaoJson { http, trecho }) => {
            json!({"erro": "nao_json", "http": http, "trecho": trecho})
        }
        Err(Erro::HsmRecusou(m)) => json!({"erro": "hsm", "mensagem": m}),
        Err(Erro::Malformada(_)) => json!({"erro": "malformada"}),
    }
}

const HSM: &str = "o HSM recusou o hash: ";

/// O antigo junta em `Error::Estado` a recusa do HSM e a resposta sem o campo
/// esperado, e chama de `Error::Cripto` o base64 inválido. O novo separa a
/// recusa do HSM (com a mesma mensagem) e chama o resto de malformada.
fn esperado(antigo: &Value) -> Value {
    match antigo["erro"].as_str() {
        Some("estado") => match s(antigo, "mensagem").strip_prefix(HSM) {
            Some(m) => json!({"erro": "hsm", "mensagem": m}),
            None => json!({"erro": "malformada"}),
        },
        Some("cripto") => json!({"erro": "malformada"}),
        _ => antigo.clone(),
    }
}

fn certificado(c: Certificado) -> Value {
    json!({"key_name": c.key_name, "serial_number": c.serial_number,
        "issue": c.issue, "base64": c.base64})
}

#[test]
fn as_respostas_sao_lidas_igual() {
    let mut diferencas = Vec::new();
    for caso in fixture("respostas.json", 150) {
        let http = caso["http"].as_u64().unwrap() as u16;
        let corpo = s(&caso, "corpo");
        let novo = match caso["endpoint"].as_str().unwrap() {
            "login" => lido(resposta::login(http, &corpo), |l| {
                json!({"token": l.token, "id": l.id, "organizacao_id": l.organizacao_id,
                    "nome": l.nome, "cpf": l.cpf})
            }),
            "registrar" => lido(
                resposta::registro(http, &corpo),
                |c| json!({"codigo_desktop": c}),
            ),
            "status_celular" => lido(
                resposta::status_celular(http, &corpo),
                |b| json!({"usuario_possui_codigo_push": b}),
            ),
            "carteira" => lido(
                resposta::carteira(http, &corpo),
                |cs| json!({"certificados": cs.into_iter().map(certificado).collect::<Vec<_>>()}),
            ),
            "tokensessao" => lido(resposta::tokensessao(http, &corpo), |t| json!({"token": t})),
            "request_hash" => lido(
                resposta::request_hash(http, &corpo),
                |a| json!({"assinatura_b64": b64(&a)}),
            ),
            outro => panic!("endpoint desconhecido: {outro}"),
        };
        let antigo = esperado(&caso["esperado"]);
        if novo != antigo {
            diferencas.push(format!(
                "{} / {} (HTTP {http}, {corpo:?})\n  novo:   {novo}\n  antigo: {antigo}",
                s(&caso, "endpoint"),
                s(&caso, "caso")
            ));
        }
    }
    conferir(diferencas);
}

#[test]
fn as_mensagens_sao_classificadas_igual() {
    let mut diferencas = Vec::new();
    for caso in fixture("classificacao.json", 70) {
        let (m, c) = (s(&caso, "mensagem"), s(&caso, "corpo"));
        let r = classificacao::classificar(&m, &c);
        let novo = json!({"origem": origem(r), "regra": regra(r),
            "falha_de_sessao": classificacao::falha_de_sessao(&m, &c)});
        let antigo = json!({"origem": caso["origem"], "regra": caso["regra"],
            "falha_de_sessao": caso["falha_de_sessao"]});
        if novo != antigo {
            diferencas.push(format!(
                "{m:?} / {c:?}\n  novo:   {novo}\n  antigo: {antigo}"
            ));
        }
    }
    conferir(diferencas);
}

#[test]
fn o_algoritmo_aceita_os_mesmos_tamanhos_e_nomes() {
    let mut diferencas = Vec::new();
    for caso in fixture("algoritmo.json", 30) {
        let (novo, antigo) = if let Some(nome) = caso["nome"].as_str() {
            (Algoritmo::do_nome(nome).is_some(), &caso["conhecido"])
        } else {
            let a = Algoritmo::do_nome(&s(&caso, "algoritmo")).unwrap();
            let tamanho = caso["tamanho"].as_u64().unwrap() as usize;
            (a.aceita(&vec![7; tamanho]), &caso["aceito"])
        };
        if json!(novo) != *antigo {
            diferencas.push(format!("{caso}: novo {novo}"));
        }
    }
    conferir(diferencas);
}

#[test]
fn a_canonica_e_o_bearer_saem_iguais() {
    let chave = chave();
    let mut diferencas = Vec::new();
    for caso in fixture("canonica.json", 13) {
        let c = canonica(&caso["corpo"]);
        let novo = json!({"canonica": c, "bearer": chave.bearer(&c)});
        let antigo = json!({"canonica": caso["canonica"], "bearer": caso["bearer"]});
        if novo != antigo {
            diferencas.push(format!(
                "{}\n  novo:   {novo}\n  antigo: {antigo}",
                caso["corpo"]
            ));
        }
    }
    conferir(diferencas);
}

#[test]
fn as_constantes_sao_as_mesmas() {
    let caminho = format!(
        "{}/tests/paridade/constantes.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let antigas: Value = serde_json::from_str(&std::fs::read_to_string(caminho).unwrap()).unwrap();
    let novas = json!({
        "remoteid_url": p::REMOTEID_URL,
        "certinext_url": p::CERTINEXT_URL,
        "certinext_base": p::CERTINEXT_BASE,
        "user_agent": p::USER_AGENT,
        "nome_aplicacao": p::NOME_APLICACAO,
        "algoritmo_padrao": Algoritmo::default().nome(),
    });
    assert_eq!(novas, antigas);
}

// --- o .p7s -------------------------------------------------------------------

#[test]
fn o_p7s_sai_byte_a_byte_igual_ao_do_antigo() {
    use remoteid::cades::Montador;
    let certificado = include_bytes!("mock/fake-cert.der");
    let mut diferencas = Vec::new();
    let casos = fixture("cades.json", 6);
    for caso in &casos {
        let nome = s(caso, "nome");
        let digest = de_b64(&s(caso, "digest")).unwrap();
        let anexar = caso["anexar"].as_str().map(|a| de_b64(a).unwrap());
        let momento = caso["momento"].as_u64().unwrap();
        let assinatura = de_b64(&s(caso, "assinatura")).unwrap();
        match (
            Montador::novo(certificado, &digest, momento, anexar, None),
            caso.get("erro"),
        ) {
            (Ok(m), None) => {
                if b64(m.a_assinar()) != s(caso, "a_assinar") {
                    diferencas.push(format!("{nome}: o que vai ao HSM"));
                }
                if b64(&m.finalizar(&assinatura).unwrap()) != s(caso, "p7s") {
                    diferencas.push(format!("{nome}: o DER do envelope"));
                }
            }
            (Err(_), Some(_)) => {}
            (Ok(_), Some(_)) => {
                diferencas.push(format!("{nome}: o antigo recusou, o novo aceitou"))
            }
            (Err(e), None) => diferencas.push(format!("{nome}: o novo recusou ({e})")),
        }
    }
    // Os dois caminhos de erro e os quatro envelopes têm de estar no corpus.
    assert_eq!(casos.iter().filter(|c| c.get("erro").is_some()).count(), 2);
    conferir(diferencas);
}
