//! A senha da conta no chaveiro do sistema.
//!
//! O "PIN" que o servidor pede para abrir a sessão de assinatura é a senha da
//! conta RemoteID, a mesma do login. Guardada no chaveiro ao entrar, a
//! assinatura só pede o código do autenticador; o fator que autentica de
//! verdade é o OTP.
//!
//! Dentro do Flatpak o `oo7` usa o portal de segredos (um arquivo cifrado por
//! aplicativo, no sandbox do Âncora, que o módulo e a janela dividem) e, sem
//! o portal, o Secret Service do host pelo D-Bus. Sem nenhum dos dois, nada é
//! guardado e a senha volta a ser pedida a cada sessão.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use futures_lite::future;

use crate::id_do_aplicativo;

/// Troca o chaveiro: [`SEM_COFRE`] não guarda nada. Os testes usam, para não
/// gravar no chaveiro de quem os roda.
pub const ENV_COFRE: &str = "REMOTEID_COFRE";
pub const SEM_COFRE: &str = "nenhum";

/// Quanto esperar o chaveiro. Trancado, ele pede a senha do chaveiro à
/// pessoa, e isso pode levar um tempo; travado, a assinatura segue pedindo a
/// senha da conta no diálogo.
const LIMITE: Duration = Duration::from_secs(90);

pub trait Cofre: Send {
    /// A senha guardada para a conta, se houver.
    fn ler(&self, email: &str) -> Option<String>;
    fn guardar(&self, email: &str, senha: &str) -> Result<(), String>;
    fn apagar(&self, email: &str) -> Result<(), String>;
}

/// O cofre que o ambiente pede: o chaveiro, ou nenhum.
pub fn do_ambiente() -> Box<dyn Cofre> {
    match std::env::var(ENV_COFRE) {
        Ok(v) if v == SEM_COFRE => Box::new(SemCofre),
        _ => Box::new(Chaveiro),
    }
}

/// Não guarda nada: a senha é pedida a cada sessão.
pub struct SemCofre;

impl Cofre for SemCofre {
    fn ler(&self, _: &str) -> Option<String> {
        None
    }

    fn guardar(&self, _: &str, _: &str) -> Result<(), String> {
        Err("sem chaveiro".into())
    }

    fn apagar(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Um cofre que vive o tempo do processo, para os testes.
#[derive(Default)]
pub struct NaMemoria(Mutex<HashMap<String, String>>);

impl Cofre for NaMemoria {
    fn ler(&self, email: &str) -> Option<String> {
        self.0.lock().ok()?.get(email).cloned()
    }

    fn guardar(&self, email: &str, senha: &str) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|e| e.to_string())?
            .insert(email.into(), senha.into());
        Ok(())
    }

    fn apagar(&self, email: &str) -> Result<(), String> {
        self.0.lock().map_err(|e| e.to_string())?.remove(email);
        Ok(())
    }
}

/// O chaveiro do sistema, pelo `oo7`.
pub struct Chaveiro;

fn atributos(email: &str) -> [(&'static str, &str); 2] {
    [("aplicativo", id_do_aplicativo()), ("conta", email)]
}

/// Roda uma chamada ao chaveiro até o fim ou até o [`LIMITE`].
fn esperar<T>(chamada: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    future::block_on(future::or(chamada, async {
        async_io::Timer::after(LIMITE).await;
        Err("o chaveiro não respondeu".to_string())
    }))
}

fn erro(e: oo7::Error) -> String {
    e.to_string()
}

async fn aberto() -> Result<oo7::Keyring, String> {
    let chaveiro = match oo7::Keyring::new().await {
        Ok(chaveiro) => chaveiro,
        // O oo7 0.6 promete cair no Secret Service quando o sandbox não tem o
        // portal de segredos, mas devolve o erro do portal antes de chegar
        // lá (medido num Hyprland, sem o portal). A queda é aqui.
        Err(portal) => {
            let servico = oo7::dbus::Service::new()
                .await
                .map_err(|e| format!("{portal}; Secret Service: {e}"))?;
            oo7::Keyring::DBus(
                servico
                    .default_collection()
                    .await
                    .map_err(|e| format!("{portal}; Secret Service: {e}"))?,
            )
        }
    };
    chaveiro.unlock().await.map_err(erro)?;
    Ok(chaveiro)
}

impl Cofre for Chaveiro {
    fn ler(&self, email: &str) -> Option<String> {
        esperar(async {
            let chaveiro = aberto().await?;
            let itens = chaveiro
                .search_items(&atributos(email))
                .await
                .map_err(erro)?;
            match itens.first() {
                Some(item) => Ok(Some(item.secret().await.map_err(erro)?)),
                None => Ok(None),
            }
        })
        .ok()
        .flatten()
        .and_then(|segredo| String::from_utf8(segredo.as_bytes().to_vec()).ok())
    }

    fn guardar(&self, email: &str, senha: &str) -> Result<(), String> {
        esperar(async {
            aberto()
                .await?
                .create_item(
                    &format!("RemoteID: senha da conta {email}"),
                    &atributos(email),
                    senha,
                    true,
                )
                .await
                .map_err(erro)
        })
    }

    fn apagar(&self, email: &str) -> Result<(), String> {
        esperar(async {
            aberto()
                .await?
                .delete(&atributos(email))
                .await
                .map_err(erro)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn na_memoria_guarda_troca_e_apaga() {
        let c = NaMemoria::default();
        assert_eq!(c.ler("a@b"), None);
        c.guardar("a@b", "um").unwrap();
        c.guardar("a@b", "dois").unwrap();
        assert_eq!(c.ler("a@b").as_deref(), Some("dois"));
        assert_eq!(c.ler("outra@b"), None);
        c.apagar("a@b").unwrap();
        assert_eq!(c.ler("a@b"), None);
    }
}
