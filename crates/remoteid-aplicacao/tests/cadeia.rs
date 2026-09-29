//! A cadeia de autoridades pelo motor (issue 22): a carteira baixa, o daemon
//! completa o que falta, e nenhuma falha de download derruba a carteira.
//!
//! Tudo por portas injetadas: o transporte devolve uma carteira enlatada com o
//! certificado SINTÉTICO do mock, e a [`FonteDeCadeia`] serve o `.p7c`
//! sintético (ou falha) e conta os pedidos. Nada vai à rede.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use remoteid_aplicacao::{Dependencias, Motor, Opcoes};
use remoteid_cripto::b64;
use remoteid_diag_jsonl::Diag;
use remoteid_estado::{Certificado, Estado};
use remoteid_portas::{
    Ambiente, CofreDeChave, Diagnostico, FonteDeCadeia, Relogio, RepositorioEstado, RequisicaoHttp,
    RespostaHttp, TransporteRemoteId,
};
use remoteid_tipos::{Error, IdInstalacao, Result};

const CERT: &[u8] = include_bytes!("../../remoteid-mock/fixtures/fake-cert.der");
const PACOTE: &[u8] = include_bytes!("../../remoteid-mock/fixtures/AC_TESTE_DESKTOPID.p7c");
const URL_AIA: &str = "http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c";
const KEY_NAME: &str = "SERIAL;CN=AC TESTE DESKTOPID, O=ICP-Brasil TESTE, C=BR";

#[derive(Clone, Default)]
struct RepoMem(Arc<Mutex<Option<Estado>>>);
impl RepositorioEstado for RepoMem {
    fn carregar(&self, _: &IdInstalacao) -> Result<Estado> {
        Ok(self.0.lock().unwrap().clone().unwrap_or_else(Estado::novo))
    }
    fn salvar(&self, _: &IdInstalacao, estado: &Estado) -> Result<()> {
        *self.0.lock().unwrap() = Some(estado.clone());
        Ok(())
    }
    fn apagar(&self, _: &IdInstalacao) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// Responde a qualquer requisição com a carteira de um certificado.
struct CarteiraEnlatada;
impl TransporteRemoteId for CarteiraEnlatada {
    fn requisitar(&self, req: &RequisicaoHttp) -> Result<RespostaHttp> {
        assert!(
            req.url.ends_with("/carteira"),
            "rota inesperada: {}",
            req.url
        );
        let corpo = json!({ "certificados": [ { "keyName": KEY_NAME, "base64": b64(CERT) } ] });
        Ok(RespostaHttp {
            status: 200,
            corpo: corpo.to_string(),
        })
    }
}

/// Serve os pacotes de um mapa URL → bytes, e registra cada pedido.
#[derive(Clone, Default)]
struct FonteFalsa {
    pacotes: Arc<HashMap<String, Vec<u8>>>,
    pedidos: Arc<Mutex<Vec<String>>>,
}
impl FonteFalsa {
    fn com_o_pacote_do_mock() -> FonteFalsa {
        FonteFalsa {
            pacotes: Arc::new(HashMap::from([(URL_AIA.to_string(), PACOTE.to_vec())])),
            ..Default::default()
        }
    }
    fn fora_do_ar() -> FonteFalsa {
        FonteFalsa::default()
    }
    fn pedidos(&self) -> Vec<String> {
        self.pedidos.lock().unwrap().clone()
    }
}
impl FonteDeCadeia for FonteFalsa {
    fn baixar(&self, url: &str) -> Result<Vec<u8>> {
        self.pedidos.lock().unwrap().push(url.to_string());
        self.pacotes
            .get(url)
            .cloned()
            .ok_or_else(|| Error::Rede(format!("{url}: HTTP 404")))
    }
}

struct CofreFalso;
impl CofreDeChave for CofreFalso {
    fn publica_pem(&self, _: &IdInstalacao) -> Result<String> {
        Err(Error::uso("stub"))
    }
    fn assinar_digest(&self, _: &IdInstalacao, _: &[u8]) -> Result<Vec<u8>> {
        Err(Error::uso("stub"))
    }
    fn assinar_pkcs1_v15_cru(&self, _: &IdInstalacao, _: &[u8]) -> Result<Vec<u8>> {
        Err(Error::uso("stub"))
    }
    fn bearer_assinado(&self, _: &IdInstalacao, _: &str) -> Result<String> {
        Ok("bearer".into())
    }
}
struct RelogioFixo;
impl Relogio for RelogioFixo {
    fn agora(&self) -> u64 {
        1_756_900_000
    }
}
struct AmbienteFalso;
impl Ambiente for AmbienteFalso {
    fn hostname(&self) -> String {
        "host-teste".into()
    }
    fn usuario_local(&self) -> String {
        "user-teste".into()
    }
}

fn motor(repo: RepoMem, fonte: FonteFalsa) -> Motor {
    let opcoes = Opcoes {
        dir_dados: "/tmp/inexistente-cadeia".into(),
        dir_diag: "/tmp/inexistente-cadeia".into(),
        remoteid_url: "http://localhost:0".into(),
        certinext_url: "http://localhost:0".into(),
        timeout: Duration::from_secs(1),
        ttl_sessao_hipotetico_s: 900,
    };
    let deps = Dependencias {
        repo: Box::new(repo),
        cofre: Box::new(CofreFalso),
        transporte: Box::new(CarteiraEnlatada),
        fonte_cadeia: Box::new(fonte),
        diag: Arc::new(Diag::inerte()) as Arc<dyn Diagnostico>,
        relogio: Box::new(RelogioFixo),
        ambiente: Box::new(AmbienteFalso),
        id: IdInstalacao::local(),
    };
    Motor::com_dependencias(opcoes, deps).unwrap()
}

/// Um estado já registrado, com a carteira de antes da cadeia existir.
fn repo_registrado(certificados: Vec<Certificado>) -> RepoMem {
    let mut e = Estado::novo();
    e.codigo_desktop = Some("codigo".into());
    e.certificados = certificados;
    let repo = RepoMem::default();
    repo.salvar(&IdInstalacao::local(), &e).unwrap();
    repo
}

fn cert_sem_cadeia() -> Certificado {
    Certificado::do_key_name(KEY_NAME, Some(b64(CERT))).unwrap()
}

/// As duas autoridades do pacote sintético, na ordem da cadeia.
fn cadeia_esperada() -> Vec<String> {
    remoteid_cadeia::montar(
        CERT,
        &remoteid_cadeia::certificados_do_pacote(PACOTE).unwrap(),
    )
    .unwrap()
    .autoridades
    .iter()
    .map(|d| b64(d))
    .collect()
}

#[test]
fn a_carteira_traz_a_cadeia_do_ca_issuers() {
    let fonte = FonteFalsa::com_o_pacote_do_mock();
    let mut m = motor(repo_registrado(vec![]), fonte.clone());

    let certs = m.carteira().unwrap();
    assert_eq!(certs[0].cadeia, cadeia_esperada());
    assert_eq!(certs[0].cadeia.len(), 2, "AC TESTE e a raiz");
    // O pacote traz a cadeia inteira: um download só, e nenhum depois da raiz.
    assert_eq!(fonte.pedidos(), vec![URL_AIA.to_string()]);
}

#[test]
fn download_que_falha_nao_derruba_a_carteira() {
    let mut m = motor(repo_registrado(vec![]), FonteFalsa::fora_do_ar());
    let certs = m.carteira().unwrap();
    assert_eq!(certs.len(), 1);
    assert!(certs[0].cadeia.is_empty());
}

#[test]
fn carteira_refeita_offline_preserva_a_cadeia_do_mesmo_certificado() {
    let mut antes = cert_sem_cadeia();
    antes.cadeia = cadeia_esperada();
    let mut m = motor(repo_registrado(vec![antes]), FonteFalsa::fora_do_ar());
    assert_eq!(m.carteira().unwrap()[0].cadeia, cadeia_esperada());
}

#[test]
fn completar_preenche_a_instalacao_antiga_e_grava() {
    let repo = repo_registrado(vec![cert_sem_cadeia()]);
    let fonte = FonteFalsa::com_o_pacote_do_mock();
    let mut m = motor(repo.clone(), fonte.clone());

    assert_eq!(m.completar_cadeias().unwrap(), 1);
    // Gravado no repositório, que é o que o módulo PKCS#11 vai ler.
    let gravado = repo.carregar(&IdInstalacao::local()).unwrap();
    assert_eq!(gravado.certificados[0].cadeia, cadeia_esperada());

    // Já completo: a próxima subida não vai à rede.
    let mut m = motor(repo, fonte.clone());
    assert_eq!(m.completar_cadeias().unwrap(), 0);
    assert_eq!(fonte.pedidos().len(), 1);
}

#[test]
fn completar_offline_nao_e_erro_e_nao_grava_nada() {
    let repo = repo_registrado(vec![cert_sem_cadeia()]);
    let fonte = FonteFalsa::fora_do_ar();
    let mut m = motor(repo.clone(), fonte.clone());

    assert_eq!(m.completar_cadeias().unwrap(), 0);
    assert_eq!(fonte.pedidos(), vec![URL_AIA.to_string()]);
    assert!(
        repo.carregar(&IdInstalacao::local()).unwrap().certificados[0]
            .cadeia
            .is_empty()
    );
}

#[test]
fn pacote_so_com_a_ac_segue_o_aia_dela_ate_desistir() {
    // Um pacote que traz só a AC (sem a raiz), e a AC sintética não declara
    // AIA: a cadeia fica incompleta, mas a intermediária entra, que é o que o
    // validador do outro lado não tem.
    let certs = remoteid_cadeia::certificados_do_pacote(PACOTE).unwrap();
    let so_ac = remoteid_cadeia::montar(CERT, &certs).unwrap().autoridades[0].clone();
    let fonte = FonteFalsa {
        pacotes: Arc::new(HashMap::from([(URL_AIA.to_string(), so_ac.clone())])),
        ..Default::default()
    };
    let mut m = motor(repo_registrado(vec![]), fonte.clone());
    assert_eq!(m.carteira().unwrap()[0].cadeia, vec![b64(&so_ac)]);
    assert_eq!(fonte.pedidos().len(), 1);
}
