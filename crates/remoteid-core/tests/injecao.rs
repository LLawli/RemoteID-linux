//! Prova de que o motor é genérico sobre as portas: `Motor::com_dependencias`
//! aceita implementações arbitrárias, e a lógica não muda.
//!
//! Aqui trocamos o armazenamento do estado por um `RepositorioEstado` EM MEMÓRIA
//! (em vez do `state.json`) e mostramos que a persistência do motor passa por
//! ele: gravar com um motor e reabrir outro, compartilhando o mesmo repositório,
//! recupera o estado. É o mesmo contrato que um adaptador Postgres cumpriria.
//!
//! Os outros adaptadores são stubs mínimos: este caminho (definir modo, salvar,
//! recarregar) não toca rede, chave, relógio nem ambiente.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use remoteid_core::authmode::Modo;
use remoteid_core::diag::Diag;
use remoteid_core::{Dependencias, Motor, Opcoes};
use remoteid_estado::Estado;
use remoteid_portas::{
    Ambiente, CofreDeChave, Diagnostico, Relogio, RepositorioEstado, RequisicaoHttp, RespostaHttp,
    TransporteRemoteId,
};
use remoteid_tipos::{Error, IdInstalacao, Result};

/// Armazenamento do estado EM MEMÓRIA, compartilhável entre motores.
#[derive(Clone, Default)]
struct RepoMem {
    dados: Arc<Mutex<HashMap<String, Estado>>>,
}
impl RepositorioEstado for RepoMem {
    fn carregar(&self, id: &IdInstalacao) -> Result<Estado> {
        Ok(self.dados.lock().unwrap().get(id.como_str()).cloned().unwrap_or_else(Estado::novo))
    }
    fn salvar(&self, id: &IdInstalacao, estado: &Estado) -> Result<()> {
        self.dados.lock().unwrap().insert(id.como_str().to_string(), estado.clone());
        Ok(())
    }
    fn apagar(&self, id: &IdInstalacao) -> Result<()> {
        self.dados.lock().unwrap().remove(id.como_str());
        Ok(())
    }
}

// Stubs para as portas que este caminho não exercita.
struct TransporteNulo;
impl TransporteRemoteId for TransporteNulo {
    fn requisitar(&self, _: &RequisicaoHttp) -> Result<RespostaHttp> {
        Err(Error::uso("o teste de injeção não vai à rede"))
    }
}
struct CofreNulo;
impl CofreDeChave for CofreNulo {
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
        Err(Error::uso("stub"))
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

fn deps_com(repo: RepoMem) -> Dependencias {
    Dependencias {
        repo: Box::new(repo),
        cofre: Box::new(CofreNulo),
        transporte: Box::new(TransporteNulo),
        diag: Arc::new(Diag::inerte()) as Arc<dyn Diagnostico>,
        relogio: Box::new(RelogioFixo),
        ambiente: Box::new(AmbienteFalso),
        id: IdInstalacao::local(),
    }
}

fn opcoes() -> Opcoes {
    Opcoes {
        dir_dados: "/tmp/inexistente-injecao".into(),
        dir_diag: "/tmp/inexistente-injecao".into(),
        remoteid_url: "http://localhost:0".into(),
        certinext_url: "http://localhost:0".into(),
        timeout: Duration::from_secs(1),
        ttl_sessao_hipotetico_s: 900,
    }
}

#[test]
fn o_motor_persiste_pelo_repositorio_injetado() {
    let repo = RepoMem::default();

    // Motor 1: muda a política de autorização e salva.
    let mut m1 = Motor::com_dependencias(opcoes(), deps_com(repo.clone())).unwrap();
    assert_eq!(m1.estado.modo(), Modo::Local, "nasce no modo padrão");
    m1.definir_modo(&Modo::Push);
    m1.salvar_estado().unwrap();

    // Motor 2, mesmo repositório em memória: enxerga o que o motor 1 gravou.
    // A troca de JSON por memória não exigiu tocar em nada do motor.
    let m2 = Motor::com_dependencias(opcoes(), deps_com(repo)).unwrap();
    assert_eq!(m2.estado.modo(), Modo::Push, "o estado veio do repositório injetado");
}
