//! O motor de ponta a ponta contra o servidor falso (`remoteid-mock`), que
//! roda como processo à parte, confere o `Bearer` de cada requisição e lembra
//! as sessões abertas.

mod comum;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Command;

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use comum::Mock;
use remoteid::cades;
use remoteid::caminhos::Caminhos;
use remoteid::cofre::{Cofre, NaMemoria};
use remoteid::cripto::sha256;
use remoteid::estado::Estado;
use remoteid::harness;
use remoteid::motor::{Autorizador, Credencial, Erro, Fatores, MAX_TENTATIVAS, Motor};
use remoteid::protocolo::requisicao::Maquina;
use remoteid::protocolo::resposta::Erro as ErroProtocolo;
use remoteid::protocolo::{Algoritmo, Certificado, Servidor};
use remoteid::transporte::{Http, TEMPO_LIMITE};

const MAQUINA: Maquina = Maquina {
    nome: "pc-de-teste",
    usuario_local: "teste",
    dominio_rede: "pc-de-teste",
};

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

/// Responde a cada pedido com o próximo item do roteiro (`None` é desistir):
/// o segredo que a credencial pediu (a senha da conta ou o PIN local; vazio
/// quando só o OTP foi pedido) e o OTP. Anota a recusa e a credencial de cada
/// pedido: `guardada`, `pin`, `senha` ou `senha:<a guardada que mostrou>`.
struct Roteiro {
    respostas: RefCell<VecDeque<Option<(&'static str, &'static str)>>>,
    recusas: RefCell<Vec<Option<String>>>,
    credenciais: RefCell<Vec<String>>,
}

impl Roteiro {
    fn novo(respostas: &[Option<(&'static str, &'static str)>]) -> Roteiro {
        Roteiro {
            respostas: RefCell::new(respostas.iter().copied().collect()),
            recusas: RefCell::new(Vec::new()),
            credenciais: RefCell::new(Vec::new()),
        }
    }

    fn certo() -> Roteiro {
        Roteiro::novo(&[Some(("teste-1234", "123456"))])
    }

    fn pedidos(&self) -> usize {
        self.recusas.borrow().len()
    }
}

impl Autorizador for Roteiro {
    fn pedir(
        &self,
        _: &Certificado,
        recusa: Option<&str>,
        credencial: Credencial<'_>,
    ) -> Option<Fatores> {
        self.recusas.borrow_mut().push(recusa.map(str::to_string));
        self.credenciais.borrow_mut().push(match credencial {
            Credencial::Guardada => "guardada".into(),
            Credencial::Pin => "pin".into(),
            Credencial::Senha { atual: None } => "senha".into(),
            Credencial::Senha { atual: Some(a) } => format!("senha:{a}"),
        });
        let (segredo, otp) = self
            .respostas
            .borrow_mut()
            .pop_front()
            .expect("o motor pediu fatores além do roteiro")?;
        let segredo = (!segredo.is_empty()).then(|| segredo.to_string());
        Some(Fatores {
            senha: matches!(credencial, Credencial::Senha { .. })
                .then(|| segredo.clone())
                .flatten(),
            pin: (credencial == Credencial::Pin).then_some(segredo).flatten(),
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
    let roteiro = Roteiro::novo(&[
        Some(("senha-errada", "123456")),
        Some(("teste-1234", "123456")),
    ]);
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
    let errado = Some(("senha-errada", "000000"));
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
    let diagnostico = Diagnostico::abrir(&caminhos.diagnostico(), "teste");
    let arquivo = diagnostico.caminho().unwrap().to_path_buf();
    let mut m = motor(&mock, &caminhos).com_diagnostico(diagnostico);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    m.assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::certo())
        .unwrap();

    let registro = std::fs::read_to_string(arquivo).unwrap();
    // A de início, uma por requisição e por resposta (login, registro, celular,
    // carteira, tokensessao e requestHash), duas pela cadeia (o download e o
    // resultado), uma pelo pedido de fatores e três pelo cofre (guardar a
    // senha do login, procurá-la antes do pedido, guardar a que abriu a
    // sessão).
    assert_eq!(registro.lines().count(), 19, "{registro}");
    assert!(registro.contains(r#""credencial":"senha""#), "{registro}");
    assert!(registro.contains(r#""evento":"pedido""#), "{registro}");
    let token = &m.estado.sessoes.values().next().unwrap().token;
    let certificado = m.estado.certificado().unwrap().base64.clone().unwrap();
    for segredo in [
        "teste-1234",           // senha
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

#[test]
fn sair_esquece_a_conta_e_guarda_a_chave_para_entrar_de_novo() {
    let mock = Mock::subir();
    let caminhos = diretorio("sair");
    let mut m = motor(&mock, &caminhos);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    m.assinar(Algoritmo::Sha256, &[1; 32], &Roteiro::certo())
        .unwrap();
    let chave = std::fs::read(caminhos.chave()).unwrap();

    m.sair().unwrap();
    assert_eq!(
        Estado::carregar(&caminhos.estado()).unwrap(),
        Estado::default()
    );
    assert_eq!(std::fs::read(caminhos.chave()).unwrap(), chave);
    assert!(matches!(
        m.assinar(Algoritmo::Sha256, &[2; 32], &Roteiro::novo(&[])),
        Err(Erro::NaoPreparado(_))
    ));

    let mut de_novo = motor(&mock, &caminhos);
    de_novo
        .preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    assert!(de_novo.estado.preparado());
}

/// Um cofre que o teste também enxerga depois de entregá-lo ao motor.
#[derive(Clone, Default)]
struct CofreDividido(std::sync::Arc<NaMemoria>);

impl Cofre for CofreDividido {
    fn ler(&self, email: &str) -> Option<String> {
        self.0.ler(email)
    }
    fn guardar(&self, email: &str, senha: &str) -> Result<(), String> {
        self.0.guardar(email, senha)
    }
    fn apagar(&self, email: &str) -> Result<(), String> {
        self.0.apagar(email)
    }
}

const EMAIL: &str = "teste@remoteid.local";

fn com_cofre(mock: &Mock, nome: &str) -> (Motor, CofreDividido) {
    let cofre = CofreDividido::default();
    let mut m = motor(mock, &diretorio(nome)).com_cofre(Box::new(cofre.clone()));
    m.preparar(EMAIL, "teste-1234", &MAQUINA).unwrap();
    (m, cofre)
}

#[test]
fn com_a_senha_guardada_ao_entrar_a_assinatura_so_pede_o_otp() {
    let mock = Mock::subir();
    let (mut m, cofre) = com_cofre(&mock, "cofre-otp");
    assert_eq!(cofre.ler(EMAIL).as_deref(), Some("teste-1234"));
    let roteiro = Roteiro::novo(&[Some(("", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    assert_eq!(*roteiro.credenciais.borrow(), ["guardada"]);
}

#[test]
fn depois_de_uma_recusa_a_senha_e_perguntada_ja_preenchida() {
    let mock = Mock::subir();
    let (mut m, _) = com_cofre(&mock, "cofre-recusa");
    // O servidor não diz se o errado é a senha ou o OTP.
    // O diálogo devolve a senha que mostrou preenchida.
    let roteiro = Roteiro::novo(&[Some(("", "000000")), Some(("teste-1234", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    assert_eq!(
        *roteiro.credenciais.borrow(),
        ["guardada", "senha:teste-1234"]
    );
}

#[test]
fn a_senha_que_o_servidor_aceita_substitui_a_guardada() {
    let mock = Mock::subir();
    let (mut m, cofre) = com_cofre(&mock, "cofre-troca");
    cofre.guardar(EMAIL, "senha-antiga").unwrap();
    let roteiro = Roteiro::novo(&[Some(("", "123456")), Some(("teste-1234", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    assert_eq!(cofre.ler(EMAIL).as_deref(), Some("teste-1234"));
}

#[test]
fn sem_cofre_a_senha_e_perguntada_toda_vez() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "sem-cofre");
    let roteiro = Roteiro::certo();
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    assert_eq!(*roteiro.credenciais.borrow(), ["senha"]);
}

#[test]
fn sair_apaga_a_senha_guardada() {
    let mock = Mock::subir();
    let (mut m, cofre) = com_cofre(&mock, "cofre-sair");
    m.sair().unwrap();
    assert_eq!(cofre.ler(EMAIL), None);
}

/// Sem chaveiro: entra, e protege a senha com o PIN `4321`.
fn com_pin(mock: &Mock, nome: &str) -> (Motor, Caminhos) {
    let caminhos = diretorio(nome);
    let mut m = motor(mock, &caminhos);
    let no_chaveiro = m.preparar(EMAIL, "teste-1234", &MAQUINA).unwrap();
    assert!(!no_chaveiro);
    m.proteger_com_pin("teste-1234", "4321").unwrap();
    (m, caminhos)
}

#[test]
fn com_chaveiro_nao_ha_arquivo_e_sem_ele_o_login_pede_o_pin() {
    let mock = Mock::subir();
    let (_, _) = com_cofre(&mock, "pin-com-chaveiro");
    assert!(
        !diretorio_existente("pin-com-chaveiro")
            .senha_cifrada()
            .exists()
    );
    let (_, caminhos) = com_pin(&mock, "pin-sem-chaveiro");
    let bruto = std::fs::read_to_string(caminhos.senha_cifrada()).unwrap();
    assert!(!bruto.contains("teste-1234"));
}

#[test]
fn o_pin_abre_a_senha_uma_vez_por_processo() {
    let mock = Mock::subir();
    let (mut m, caminhos) = com_pin(&mock, "pin-processo");
    let primeira = Roteiro::novo(&[Some(("4321", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[1; 32], &primeira).unwrap();
    assert_eq!(*primeira.credenciais.borrow(), ["pin"]);

    // A sessão vence; o mesmo processo ainda conhece a senha.
    mock.expirar_sessoes();
    let segunda = Roteiro::novo(&[Some(("", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[2; 32], &segunda).unwrap();
    assert_eq!(*segunda.credenciais.borrow(), ["guardada"]);

    // Outro processo, e a sessão vencida: o PIN de novo.
    mock.expirar_sessoes();
    let mut outro = motor(&mock, &caminhos);
    let terceira = Roteiro::novo(&[Some(("4321", "123456"))]);
    outro
        .assinar(Algoritmo::Sha256, &[3; 32], &terceira)
        .unwrap();
    assert_eq!(*terceira.credenciais.borrow(), ["pin"]);
}

#[test]
fn pin_errado_avisa_quantos_restam_sem_gastar_tentativa_no_servidor() {
    let mock = Mock::subir();
    let (mut m, _) = com_pin(&mock, "pin-errado-local");
    let errado = Some(("0000", "123456"));
    let mut respostas = vec![errado; MAX_TENTATIVAS as usize];
    respostas.push(Some(("4321", "123456")));
    let roteiro = Roteiro::novo(&respostas);
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    let recusas = roteiro.recusas.borrow();
    assert_eq!(recusas[0], None);
    assert!(
        recusas[1]
            .as_deref()
            .unwrap()
            .starts_with("PIN incorreto: mais 4 erros"),
        "{recusas:?}"
    );
    assert!(recusas[3].as_deref().unwrap().contains("mais 2 erros"));
}

#[test]
fn o_limite_de_pins_errados_apaga_o_arquivo_e_sai_da_conta() {
    let mock = Mock::subir();
    let (mut m, caminhos) = com_pin(&mock, "pin-bloqueado");
    let roteiro = Roteiro::novo(&[Some(("0000", "123456")); remoteid::pin::MAX_ERROS as usize]);
    let r = m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro);
    assert!(matches!(r, Err(Erro::PinBloqueado)), "{r:?}");
    assert!(!caminhos.senha_cifrada().exists());
    assert_eq!(
        Estado::carregar(&caminhos.estado()).unwrap(),
        Estado::default()
    );
}

#[test]
fn a_senha_trocada_e_cifrada_de_novo_com_o_pin_da_memoria() {
    let mock = Mock::subir();
    let caminhos = diretorio("pin-troca");
    let mut m = motor(&mock, &caminhos);
    m.preparar(EMAIL, "teste-1234", &MAQUINA).unwrap();
    // O arquivo guarda uma senha que a conta já não usa.
    m.proteger_com_pin("senha-antiga", "4321").unwrap();
    let roteiro = Roteiro::novo(&[Some(("4321", "123456")), Some(("teste-1234", "123456"))]);
    m.assinar(Algoritmo::Sha256, &[1; 32], &roteiro).unwrap();
    assert_eq!(*roteiro.credenciais.borrow(), ["pin", "senha:senha-antiga"]);

    mock.expirar_sessoes();
    let mut outro = motor(&mock, &caminhos);
    let depois = Roteiro::novo(&[Some(("4321", "123456"))]);
    outro.assinar(Algoritmo::Sha256, &[2; 32], &depois).unwrap();
    assert_eq!(*depois.credenciais.borrow(), ["pin"]);
}

fn diretorio_existente(nome: &str) -> Caminhos {
    Caminhos {
        raiz: PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("motor-{nome}")),
    }
}

// --- o .p7s e o harness -------------------------------------------------------

const AGORA: u64 = 1_800_000_000; // 2027-01-15, dentro da validade do certificado falso

/// O `openssl cms -verify` com a cadeia de teste: confere a assinatura sobre
/// os atributos, o `messageDigest` contra o documento, o
/// `signingCertificateV2` e o caminho até a raiz.
fn openssl_aceita(nome: &str, p7s: &[u8], documento: Option<&[u8]>) -> bool {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("p7s-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.p7s"), p7s).unwrap();
    let mock = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mock");
    let mut cmd = Command::new("openssl");
    cmd.args([
        "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any",
    ])
    .args(["-attime", &AGORA.to_string()])
    .arg("-in")
    .arg(dir.join("a.p7s"))
    .arg("-CAfile")
    .arg(format!("{mock}/fake-ac-raiz.pem"))
    .arg("-certfile")
    .arg(format!("{mock}/fake-ac.pem"))
    .arg("-out")
    .arg(dir.join("saida"));
    if let Some(documento) = documento {
        std::fs::write(dir.join("documento"), documento).unwrap();
        cmd.arg("-content").arg(dir.join("documento"));
    }
    let saida = cmd.output().expect("openssl no PATH");
    let aceito = saida.status.success();
    if aceito && documento.is_none() {
        // Anexado: o que sai é o documento de dentro do envelope.
        assert_eq!(
            std::fs::read(dir.join("saida")).unwrap(),
            b"contrato de teste"
        );
    }
    aceito
}

#[test]
fn o_p7s_destacado_passa_no_openssl_e_nao_com_outro_documento() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "p7s-destacado");
    let documento = b"contrato de teste";
    let p7s = cades::assinar(&mut m, &sha256(documento), None, AGORA, &Roteiro::certo()).unwrap();
    assert!(openssl_aceita("destacado", &p7s, Some(documento)));
    assert!(!openssl_aceita(
        "trocado",
        &p7s,
        Some(b"contrato de teste!")
    ));
}

#[test]
fn o_p7s_anexado_leva_o_documento_e_passa_no_openssl() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "p7s-anexado");
    let documento = b"contrato de teste".to_vec();
    let p7s = cades::assinar(
        &mut m,
        &sha256(&documento),
        Some(documento),
        AGORA,
        &Roteiro::certo(),
    )
    .unwrap();
    assert!(openssl_aceita("anexado", &p7s, None));
}

#[test]
fn o_p7s_usa_a_sessao_em_cache_como_o_token() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "p7s-cache");
    let roteiro = Roteiro::certo();
    for _ in 0..2 {
        cades::assinar(&mut m, &[3; 32], None, AGORA, &roteiro).unwrap();
    }
    assert_eq!(roteiro.pedidos(), 1);
}

#[test]
fn sem_carteira_o_p7s_nao_vai_a_rede() {
    let mock = Mock::subir();
    let mut m = motor(&mock, &diretorio("p7s-sem-conta"));
    let erro = cades::assinar(&mut m, &[3; 32], None, AGORA, &Roteiro::novo(&[])).unwrap_err();
    assert!(matches!(erro, Erro::NaoPreparado(_)), "{erro:?}");
}

fn marcas(r: &harness::Relatorio) -> Vec<(&'static str, harness::Marca)> {
    r.passos.iter().map(|p| (p.rotulo, p.marca)).collect()
}

#[test]
fn o_harness_com_a_conta_entrada_passa_inteiro_e_grava_sem_segredo() {
    use harness::Marca::Ok as M;
    let mock = Mock::subir();
    let caminhos = diretorio("harness");
    let mut m = motor(&mock, &caminhos);
    m.preparar("teste@remoteid.local", "teste-1234", &MAQUINA)
        .unwrap();
    let mut vistos = 0;
    let r = harness::rodar(&mut m, &Roteiro::certo(), AGORA, None, |_| vistos += 1);
    assert_eq!(
        marcas(&r),
        [
            ("ambiente", M),
            ("conectividade", M),
            ("conta", M),
            ("carteira", M),
            ("cadeia", M),
            ("assinatura", M),
            ("p7s", M)
        ]
    );
    assert_eq!(vistos, r.passos.len());
    assert!(!r.falhou());

    let caminho = r.salvar(&caminhos.diagnostico()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let modo = std::fs::metadata(&caminho).unwrap().permissions().mode();
    assert_eq!(modo & 0o777, 0o600);
    let texto = std::fs::read_to_string(&caminho).unwrap();
    assert!(texto.contains("sessão nova, 1 pedido"), "{texto}");
    assert!(texto.contains("AC TESTE DESKTOPID"), "{texto}");
    for proibido in [
        "teste-1234",
        "123456",
        "teste@remoteid.local",
        "DESKTOPID:",
        "00000000000",
        "16C3F7EF",
        "jwt",
    ] {
        assert!(
            !texto.contains(proibido),
            "{proibido} no relatório:\n{texto}"
        );
    }
}

#[test]
fn o_harness_so_diz_sessao_em_cache_quando_nada_foi_pedido() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "harness-cache");
    let roteiro = Roteiro::novo(&[
        Some(("teste-1234", "123456")),
        Some(("teste-1234", "123456")),
    ]);
    let assinatura = |m: &mut Motor| {
        let r = harness::rodar(m, &roteiro, AGORA, None, |_| {});
        r.passos
            .iter()
            .find(|p| p.rotulo == "assinatura")
            .unwrap()
            .detalhe
            .clone()
    };
    assert!(assinatura(&mut m).starts_with("sessão nova"));
    assert!(assinatura(&mut m).starts_with("sessão em cache"));
    // Guardada no estado, mas esquecida pelo servidor: pede de novo.
    mock.expirar_sessoes();
    assert!(assinatura(&mut m).starts_with("sessão nova"));
    assert_eq!(roteiro.pedidos(), 2);
}

#[test]
fn o_harness_sem_conta_marca_onde_parou_e_pula_o_resto() {
    use harness::Marca::{Falha, Ok as M, Pulado};
    let mock = Mock::subir();
    let mut m = motor(&mock, &diretorio("harness-sem-conta"));
    let r = harness::rodar(&mut m, &Roteiro::novo(&[]), AGORA, None, |_| {});
    assert_eq!(
        marcas(&r),
        [
            ("ambiente", M),
            ("conectividade", M),
            ("conta", Falha),
            ("carteira", Pulado),
            ("cadeia", Pulado),
            ("assinatura", Pulado),
            ("p7s", Pulado)
        ]
    );
    assert!(r.falhou());
}

#[test]
fn o_harness_registra_quem_desistiu_do_codigo() {
    let mock = Mock::subir();
    let mut m = preparado(&mock, "harness-cancelado");
    let r = harness::rodar(&mut m, &Roteiro::novo(&[None]), AGORA, None, |_| {});
    let assinatura = r.passos.iter().find(|p| p.rotulo == "assinatura").unwrap();
    assert_eq!(assinatura.marca, harness::Marca::Falha);
    assert!(
        assinatura.detalhe.contains("Cancelado"),
        "{}",
        assinatura.detalhe
    );
    assert_eq!(r.passos.last().unwrap().marca, harness::Marca::Pulado);
}
