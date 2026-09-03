//! `GtkPrompter`: o cache do PIN e a ponte para o diálogo GTK4 de PIN/OTP.
//!
//! Este módulo é do BINÁRIO, não da lib (o `main.rs` o declara com
//! `mod gtk_prompter;`). O DESENHO do diálogo não mora aqui: ele é
//! `remoteid_gtk::telas::pin_otp`, compartilhado com a janela principal, para
//! que o testador valide no `remoteid-gtk --preview` exatamente a tela que o
//! daemon mostra ao assinar. Aqui fica só o que é do daemon: o cache do PIN em
//! memória e a tradução do resultado para [`Fatores`]/[`Error`].
//!
//! ## Por que `GtkPrompter` é `Send + Sync`
//!
//! O trait exige. Os campos são só um `RwLock<Option<PinEmCache>>` e um
//! `Duration` — ambos `Send + Sync`. Os objetos GTK (`!Send`) nascem e morrem
//! dentro de `remoteid_gtk::telas::pin_otp::rodar_modal`, na thread do loop do
//! socket (a principal), nunca são guardados na struct.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use remoteid_core::authmode::Fatores;
use remoteid_core::error::{Error, Result};

use remoteid_daemon::prompter::{Contexto, Prompter};

/// TTL padrão do cache do PIN: 5 minutos (decisão de 03/09/2026, ver
/// [[remoteid-app-gtk-decisoes-tomadas]]). Configurável pela aba de
/// configurações da janela.
pub const TTL_PIN_PADRAO: Duration = Duration::from_secs(5 * 60);

/// O PIN cacheado e o instante em que entrou no cache. Só na memória do
/// daemon: nunca vai a disco, e some no kill/timeout/reset.
struct PinEmCache {
    pin: String,
    gravado_em: Instant,
}

/// Prompter de PIN/OTP com cache do PIN em memória.
///
/// O PIN do certificado é fixo (definido na emissão), então cacheá-lo entre
/// assinaturas próximas poupa um campo do diálogo. O OTP é single-use e
/// temporizado (~30s): NUNCA é cacheado, é sempre pedido.
pub struct GtkPrompter {
    cache_pin: RwLock<Option<PinEmCache>>,
    ttl_pin: Duration,
}

impl GtkPrompter {
    /// Cria o prompter com o TTL padrão ([`TTL_PIN_PADRAO`]).
    pub fn novo() -> Self {
        GtkPrompter::com_ttl(TTL_PIN_PADRAO)
    }

    /// Cria o prompter com um TTL específico. `Duration::ZERO` desliga o
    /// cache do PIN (a aba de configurações expõe isso como "0 minutos").
    pub fn com_ttl(ttl_pin: Duration) -> Self {
        GtkPrompter { cache_pin: RwLock::new(None), ttl_pin }
    }

    /// O PIN cacheado, se existe e ainda não venceu. Com `ttl_pin` zero o
    /// cache está desligado e isto devolve sempre `None`.
    fn pin_cacheado(&self) -> Option<String> {
        if self.ttl_pin.is_zero() {
            return None;
        }
        let guarda = self.cache_pin.read().ok()?;
        let c = guarda.as_ref()?;
        (c.gravado_em.elapsed() <= self.ttl_pin).then(|| c.pin.clone())
    }

    /// Grava o PIN no cache com carimbo novo. Só é chamado depois de o
    /// usuário CONFIRMAR o diálogo. Com `ttl_pin` zero não grava.
    fn guardar_pin(&self, pin: &str) {
        if self.ttl_pin.is_zero() {
            return;
        }
        if let Ok(mut g) = self.cache_pin.write() {
            *g = Some(PinEmCache { pin: pin.to_string(), gravado_em: Instant::now() });
        }
    }
}

impl Prompter for GtkPrompter {
    fn pedir_pin_otp(&self, contexto: &Contexto) -> Result<Fatores> {
        let pin_inicial = self.pin_cacheado();
        // Desenho e loop do diálogo vivem na lib de UI compartilhada.
        let saida = remoteid_gtk::telas::pin_otp::rodar_modal(
            contexto.titular.as_deref(),
            contexto.hospedeiro.as_deref(),
            pin_inicial.as_deref(),
        )
        .map_err(Error::uso)?;

        match saida {
            Some((pin, otp)) => {
                // Só cacheia o PIN do caminho confirmado. O OTP nunca é cacheado.
                self.guardar_pin(&pin);
                Ok(Fatores::PinOtp { pin, otp })
            }
            None => Err(Error::uso("cancelado pelo usuário no diálogo")),
        }
    }
}

#[cfg(test)]
mod tests {
    // Testa só a lógica do cache do PIN — nada de GTK aqui, então não abre
    // janela nem exige display.
    use super::*;

    #[test]
    fn cache_vazio_no_inicio() {
        let p = GtkPrompter::novo();
        assert_eq!(p.pin_cacheado(), None);
    }

    #[test]
    fn guarda_e_devolve_dentro_do_ttl() {
        let p = GtkPrompter::com_ttl(Duration::from_secs(60));
        p.guardar_pin("1234");
        assert_eq!(p.pin_cacheado().as_deref(), Some("1234"));
    }

    #[test]
    fn ttl_zero_desliga_o_cache() {
        // "0 minutos" na aba de configurações: guardar não persiste nada.
        let p = GtkPrompter::com_ttl(Duration::ZERO);
        p.guardar_pin("1234");
        assert_eq!(p.pin_cacheado(), None);
    }

    #[test]
    fn pin_vencido_nao_e_devolvido() {
        // TTL mínimo + espera curta: determinístico, sem sleep longo.
        let p = GtkPrompter::com_ttl(Duration::from_millis(1));
        p.guardar_pin("1234");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(p.pin_cacheado(), None);
    }
}
