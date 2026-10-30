//! O motor de ponta a ponta contra o servidor falso (`remoteid-mock`), que
//! roda como processo à parte, confere o `Bearer` de cada requisição e lembra
//! as sessões abertas.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use remoteid::caminhos::Caminhos;
use remoteid::cripto::sha256;
use remoteid::estado::Estado;
use remoteid::motor::{Autorizador, Erro, Fatores, MAX_TENTATIVAS, Motor};
use remoteid::protocolo::requisicao::Maquina;
use remoteid::protocolo::resposta::Erro as ErroProtocolo;
use remoteid::protocolo::{Algoritmo, Certificado, Servidor};
use remoteid::transporte::{Http, TEMPO_LIMITE};

const MAQUINA: Maquina = Maquina {
    nome: "pc-de-teste",
    usuario_local: "teste",
    dominio_rede: "pc-de-teste",
};

/// O servidor falso, morto quando o teste acaba.
struct Mock {
    processo: Child,
    url: String,
}

impl Mock {
    fn subir() -> Mock {
        let mut processo = Command::new(env!("CARGO_BIN_EXE_remoteid-mock"))
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut url = String::new();
        BufReader::new(processo.stdout.take().unwrap())
            .read_line(&mut url)
            .unwrap();
        Mock {
            processo,
            url: url.trim().to_string(),
        }
    }

    fn servidor(&self) -> Servidor {
        Servidor::falso(&self.url)
    }

    /// Esquece as sessões, como o servidor real faz quando elas vencem.
    fn expirar_sessoes(&self) {
        ureq::post(format!("{}/_mock/expirar", self.url))
            .send_empty()
            .unwrap();
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
    }
}

/// Um diretório só deste teste, dentro do `target/` (no SSD de dados), com
/// uma chave da instalação pronta: gerar RSA-2048 num build de debug leva
/// segundos, e só [`a_chave_nasce_na_primeira_vez_so_para_o_dono`] precisa disso.
fn diretorio(nome: &str) -> Caminhos {
    let caminhos = diretorio_vazio(nome);
    std::fs::create_dir_all(&caminhos.raiz).unwrap();
    std::fs::write(caminhos.chave(), include_str!("paridade/chave-teste.pem")).unwrap();
    caminhos
}

fn diretorio_vazio(nome: &str) -> Caminhos {
    let raiz = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("motor-{nome}"));
    let _ = std::fs::remove_dir_all(&raiz);
    Caminhos { raiz }
}

fn motor(mock: &Mock, caminhos: &Caminhos) -> Motor {
    Motor::abrir(
        caminhos.clone(),
        mock.servidor(),
        Box::new(Http::novo(TEMPO_LIMITE)),
    )
    .unwrap()
}

fn preparado(mock: &Mock, nome: &str) -> Motor {
    let mut m = motor(mock, &diretorio(nome));
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    m
}

/// Responde a cada pedido com o próximo item do roteiro (`None` é desistir),
/// e anota a recusa que acompanhou cada pedido.
struct Roteiro {
    respostas: RefCell<VecDeque<Option<(&'static str, &'static str)>>>,
    recusas: RefCell<Vec<Option<String>>>,
}

impl Roteiro {
    fn novo(respostas: &[Option<(&'static str, &'static str)>]) -> Roteiro {
        Roteiro {
            respostas: RefCell::new(respostas.iter().copied().collect()),
            recusas: RefCell::new(Vec::new()),
        }
    }

    fn certo() -> Roteiro {
        Roteiro::novo(&[Some(("1234", "123456"))])
    }

    fn pedidos(&self) -> usize {
        self.recusas.borrow().len()
    }
}

impl Autorizador for Roteiro {
    fn pedir(&self, _: &Certificado, recusa: Option<&str>) -> Option<Fatores> {
        self.recusas.borrow_mut().push(recusa.map(str::to_string));
        let (pin, otp) = self
            .respostas
            .borrow_mut()
            .pop_front()
            .expect("o motor pediu fatores além do roteiro")?;
        Some(Fatores {
            pin: pin.into(),
            otp: otp.into(),
        })
    }
}

fn chave_do_titular() -> RsaPublicKey {
    let privada = RsaPrivateKey::from_pkcs8_pem(include_str!("mock/fake-key.pem")).unwrap();
    RsaPublicKey::from(&privada)
}

#[test]
fn prepara_e_assina_e_a_assinatura_confere_com_o_certificado() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "assina");
    assert!(m.estado.preparado());
    assert_eq!(m.estado.nome.as_deref(), Some("TESTE DESKTOPID"));
    assert_eq!(m.estado.celular_pareado, Some(false));
    assert_eq!(
        m.estado.certificado().unwrap().serial_number,
        "16C3F7EFA6CCE55817FA659DC8EAA29B7E512621"
    );
    // A AC e a raiz, baixadas do caIssuers do certificado.
    assert_eq!(m.estado.certificado().unwrap().cadeia.len(), 2);

    let digest = sha256(b"contrato");
    let roteiro = Roteiro::certo();
    let assinatura = m.assinar(Algoritmo::Sha256, &digest, &roteiro).unwrap();
    chave_do_titular()
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &assinatura)
        .expect("a assinatura tem de conferir com a chave do certificado");
    assert_eq!(roteiro.pedidos(), 1);
}

#[test]
fn a_sessao_em_cache_assina_sem_pedir_nada_e_sobrevive_ao_processo() {
    let mock = Mock::subir();
    let caminhos = diretorio("cache");
    let mut m = motor(&mock, &caminhos);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    m.assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::certo())
        .unwrap();

    let nada = Roteiro::novo(&[]);
    m.assinar(Algoritmo::Sha256, &[2; 32], &nada).unwrap();
    // Outro processo (o módulo PKCS#11, a janela) abre o mesmo estado.
    let mut outro = motor(&mock, &caminhos);
    outro.assinar(Algoritmo::Sha256, &[3; 32], &nada).unwrap();
    assert_eq!(nada.pedidos(), 0);
}

#[test]
fn sessao_vencida_pede_pin_e_otp_e_assina_na_mesma_chamada() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "vencida");
    m.assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::certo())
        .unwrap();
    mock.expirar_sessoes();

    let roteiro = Roteiro::certo();
    let digest = [9; 32];
    let assinatura = m.assinar(Algoritmo::Sha256, &digest, &roteiro).unwrap();
    chave_do_titular()
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &assinatura)
        .unwrap();
    assert_eq!(*roteiro.recusas.borrow(), vec![None]);
}

#[test]
fn pin_errado_pede_de_novo_mostrando_a_recusa() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "pin-errado");
    let roteiro = Roteiro::novo(&[Some(("0000", "123456")), Some(("1234", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    assert_eq!(
        *roteiro.recusas.borrow(),
        vec![None, Some("PIN ou e-Token incorreto".into())]
    );
}

#[test]
fn as_tentativas_acabam_e_o_erro_sobe_classificado() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "tentativas");
    let errado = Some(("0000", "000000"));
    let roteiro = Roteiro::novo(&[errado; MAX_TENTATIVAS as usize]);
    match m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro) {
        Err(Erro::Protocolo(ErroProtocolo::Servidor { regra: Some(r), .. })) => {
            assert_eq!(r.fragmento, "pin ou e-token incorreto");
        }
        outro => panic!("esperava a recusa do fator: {outro:?}"),
    }
    assert_eq!(roteiro.pedidos(), MAX_TENTATIVAS as usize);
    assert!(
        m.estado.sessoes.is_empty(),
        "sessão recusada não fica em cache"
    );
}

#[test]
fn desistir_do_pedido_cancela() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "cancela");
    let r = m.assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::novo(&[None]));
    assert!(matches!(r, Err(Erro::Cancelado)), "{r:?}");
}

#[test]
fn modo_cru_assina_o_bloco_pronto() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "cru");
    // DigestInfo(MD5), como o PJeOffice manda.
    let mut bloco = vec![
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10,
    ];
    bloco.extend([7; 16]);
    let assinatura = m
        .assinar(Algoritmo::Cru, &bloco, &Roteiro::certo())
        .unwrap();
    chave_do_titular()
        .verify(Pkcs1v15Sign::new_unprefixed(), &bloco, &assinatura)
        .unwrap();
}

#[test]
fn bloco_que_o_servidor_recusaria_nao_gasta_otp() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "bloco");
    let nada = Roteiro::novo(&[]);
    for (algoritmo, tamanho) in [
        (Algoritmo::Sha256, 20),
        (Algoritmo::Cru, 246),
        (Algoritmo::Cru, 0),
    ] {
        let r = m.assinar(algoritmo, &vec![1; tamanho], &nada);
        assert!(
            matches!(r, Err(Erro::BlocoInvalido)),
            "{algoritmo:?} {tamanho}: {r:?}"
        );
    }
    assert_eq!(nada.pedidos(), 0);
}

#[test]
fn senha_errada_e_erro_da_pessoa() {
    let mock = Mock::subir();
    let mut m = motor(&mock, &diretorio("senha"));
    match m.preparar("teste@remoteid.local", "errada", &MAQUINA) {
        Err(Erro::Protocolo(ErroProtocolo::Servidor {
            http,
            regra: Some(r),
            ..
        })) => {
            assert_eq!(http, 500);
            assert_eq!(r.fragmento, "senha inv");
        }
        outro => panic!("{outro:?}"),
    }
    assert!(!m.estado.preparado());
}

#[test]
fn trocar_a_chave_depois_do_registro_e_recusado_pelo_servidor() {
    // O Bearer só vale com a chave que o registro entregou: é o que o
    // servidor falso confere, e o que pega um Bearer mal assinado.
    let mock = Mock::subir();
    let caminhos = diretorio("chave-trocada");
    let mut m = motor(&mock, &caminhos);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    std::fs::remove_file(caminhos.chave()).unwrap();
    let mut outro = motor(&mock, &caminhos);
    match outro.atualizar_carteira() {
        Err(Erro::Protocolo(ErroProtocolo::Servidor { regra: Some(r), .. })) => {
            assert_eq!(r.fragmento, "código de autorização inválida");
        }
        r => panic!("{r:?}"),
    }
}

#[test]
fn a_chave_nasce_na_primeira_vez_so_para_o_dono() {
    use std::os::unix::fs::PermissionsExt;
    let mock = Mock::subir();
    let caminhos = diretorio_vazio("permissoes");
    let mut m = motor(&mock, &caminhos);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    for arquivo in [caminhos.estado(), caminhos.chave()] {
        let modo = std::fs::metadata(&arquivo).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o600, "{}", arquivo.display());
    }
}

#[test]
fn o_diagnostico_registra_o_fluxo_sem_segredo_nem_dado_do_titular() {
    use remoteid::diagnostico::Diagnostico;
    let mock = Mock::subir();
    let caminhos = diretorio("diagnostico");
    let diagnostico = Diagnostico::abrir(&caminhos.diagnostico());
    let arquivo = diagnostico.caminho().unwrap().to_path_buf();
    let mut m = motor(&mock, &caminhos).com_diagnostico(diagnostico);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    m.assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::certo())
        .unwrap();

    let registro = std::fs::read_to_string(arquivo).unwrap();
    // Uma linha por requisição e por resposta (login, registro, celular,
    // carteira, tokensessao e requestHash), duas pela cadeia (o download e o
    // resultado) e uma pelo pedido de fatores.
    assert_eq!(registro.lines().count(), 15, "{registro}");
    assert!(registro.contains(r#""evento":"pedido""#), "{registro}");
    let token = &m.estado.sessoes.values().next().unwrap().token;
    let certificado = m.estado.certificado().unwrap().base64.clone().unwrap();
    for segredo in [
        "teste-1234",           // senha
        "\"1234\"",             // PIN
        "\"123456\"",           // OTP
        "teste@remoteid.local", // e-mail
        "\"TESTE DESKTOPID\"",  // nome do titular
        "00000000000",          // CPF
        "16C3F7EFA6CCE55817FA", // serial
        "jwt.do.login",         // JWT do login
        token,
        &certificado[..40],
    ] {
        assert!(!registro.contains(segredo), "{segredo} vazou:\n{registro}");
    }
    assert!(
        registro.contains("/api/signature/tokensessao"),
        "{registro}"
    );
}

#[test]
fn escritas_ao_mesmo_tempo_nao_se_apagam() {
    let caminho = diretorio_vazio("concorrente").estado();
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let caminho = caminho.clone();
            std::thread::spawn(move || {
                for i in 0..20 {
                    Estado::alterar(&caminho, |e| {
                        e.guardar_sessao(format!("{t}-{i}"), "t".into(), 0);
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(Estado::carregar(&caminho).unwrap().sessoes.len(), 8 * 20);
}

#[test]
fn a_escrita_de_um_processo_nao_apaga_a_do_outro() {
    let mock = Mock::subir();
    let caminhos = diretorio("dois-processos");
    let mut janela = motor(&mock, &caminhos);
    janela
        .preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    // O módulo leu o estado antes de a janela gravar a escolha, e grava a
    // sessão nova depois.
    let mut modulo = motor(&mock, &caminhos);
    let chave = janela.estado.certificado().unwrap().chave();
    janela.escolher_certificado(&chave).unwrap();
    modulo
        .assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::certo())
        .unwrap();

    let disco = Estado::carregar(&caminhos.estado()).unwrap();
    assert_eq!(disco.certificado_ativo.as_deref(), Some(chave.as_str()));
    assert_eq!(disco.sessoes.len(), 1);
}

#[test]
fn uma_ac_fora_do_ar_nao_impede_a_carteira_nem_apaga_a_cadeia_que_havia() {
    let mock = Mock::subir();
    let caminhos = diretorio("cadeia-fora-do-ar");
    let mut m = motor(&mock, &caminhos);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    assert_eq!(m.estado.certificado().unwrap().cadeia.len(), 2);

    // Uma porta que acabou de ser liberada: ninguém escuta nela.
    let porta = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let servidor = Servidor {
        repositorio: Some(format!("http://127.0.0.1:{porta}")),
        ..mock.servidor()
    };
    let mut sem_ac = Motor::abrir(
        caminhos.clone(),
        servidor,
        Box::new(Http::novo(TEMPO_LIMITE)),
    )
    .unwrap();
    sem_ac.atualizar_carteira().unwrap();
    assert_eq!(sem_ac.estado.certificado().unwrap().cadeia.len(), 2);

    let vazio = diretorio("cadeia-nunca");
    std::fs::copy(caminhos.chave(), vazio.chave()).unwrap();
    let servidor = Servidor {
        repositorio: Some(format!("http://127.0.0.1:{porta}")),
        ..mock.servidor()
    };
    let mut novo = Motor::abrir(vazio, servidor, Box::new(Http::novo(TEMPO_LIMITE))).unwrap();
    novo.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    assert!(novo.estado.certificado().unwrap().cadeia.is_empty());
}
