//! Implementação do trait `Prompter` via interface GTK4 com cache de PIN em memória.
//!
//! O `GtkPrompter` gerencia o tempo de vida do PIN em memória (TTL configurável)
//! e delega ao diálogo modal (`crate::telas::pin_otp`) a coleta dos fatores.
//! Como `Prompter` exige `Send + Sync`, a estrutura armazena apenas tipos seguros
//! para concorrência (`RwLock`, `Duration`), e os objetos de interface nascem
//! e morrem na thread principal durante o loop do diálogo.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use gtk::prelude::*;

use remoteid_autorizacao::Fatores;
use remoteid_daemon::prompter::{Contexto, Prompter};
use remoteid_tipos::Result;

/// TTL padrão do cache de PIN: 5 minutos.
pub const TTL_PIN_PADRAO: Duration = Duration::from_secs(5 * 60);

/// Registro do PIN em cache na memória do processo.
struct PinCacheado {
    pin: String,
    gravado_em: Instant,
}

/// Adaptador `Prompter` que abre o diálogo GTK4 de PIN e OTP.
pub struct GtkPrompter {
    cache_pin: RwLock<Option<PinCacheado>>,
    ttl_pin: Duration,
}

impl GtkPrompter {
    /// Cria uma nova instância com o TTL padrão de 5 minutos.
    pub fn novo() -> Self {
        Self::com_ttl(TTL_PIN_PADRAO)
    }

    /// Cria uma nova instância com TTL customizado (zero desativa o cache).
    pub fn com_ttl(ttl_pin: Duration) -> Self {
        GtkPrompter {
            cache_pin: RwLock::new(None),
            ttl_pin,
        }
    }

    /// Atualiza o TTL configurado para o cache de PIN.
    pub fn definir_ttl(&mut self, ttl: Duration) {
        self.ttl_pin = ttl;
        if ttl.is_zero() {
            self.limpar_cache();
        }
    }

    /// Limpa o cache de PIN em memória imediatamente.
    pub fn limpar_cache(&self) {
        if let Ok(mut guarda) = self.cache_pin.write() {
            *guarda = None;
        }
    }

    /// Retorna o PIN armazenado caso o cache ainda seja válido.
    pub fn pin_cacheado(&self) -> Option<String> {
        if self.ttl_pin.is_zero() {
            return None;
        }
        let guarda = self.cache_pin.read().ok()?;
        let entrada = guarda.as_ref()?;
        if entrada.gravado_em.elapsed() <= self.ttl_pin {
            Some(entrada.pin.clone())
        } else {
            None
        }
    }

    /// Armazena o PIN em memória com carimbo de tempo atual.
    fn guardar_pin(&self, pin: &str) {
        if self.ttl_pin.is_zero() {
            return;
        }
        if let Ok(mut guarda) = self.cache_pin.write() {
            *guarda = Some(PinCacheado {
                pin: pin.to_string(),
                gravado_em: Instant::now(),
            });
        }
    }
}

impl Default for GtkPrompter {
    fn default() -> Self {
        Self::novo()
    }
}

impl Prompter for GtkPrompter {
    fn pedir_pin_otp(&self, contexto: &Contexto) -> Result<Fatores> {
        let pin_inicial = self.pin_cacheado();

        // Localiza a janela ativa da aplicação para ancorar o diálogo modal flutuante
        let janela_pai = gtk::gio::Application::default()
            .and_downcast::<gtk::Application>()
            .and_then(|app| app.active_window());

        let resultado = crate::telas::pin_otp::rodar_modal(
            janela_pai.as_ref(),
            contexto.titular.as_deref(),
            contexto.hospedeiro.as_deref(),
            pin_inicial.as_deref(),
        )?;

        if let Fatores::PinOtp { ref pin, .. } = resultado {
            self.guardar_pin(pin);
        }

        Ok(resultado)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_inicia_vazio() {
        let p = GtkPrompter::novo();
        assert_eq!(p.pin_cacheado(), None);
    }

    #[test]
    fn armazena_e_recupera_dentro_do_ttl() {
        let p = GtkPrompter::com_ttl(Duration::from_secs(60));
        p.guardar_pin("9876");
        assert_eq!(p.pin_cacheado().as_deref(), Some("9876"));
    }

    #[test]
    fn ttl_zero_desativa_o_armazenamento() {
        let p = GtkPrompter::com_ttl(Duration::ZERO);
        p.guardar_pin("9876");
        assert_eq!(p.pin_cacheado(), None);
    }

    #[test]
    fn expira_quando_passado_o_ttl() {
        let p = GtkPrompter::com_ttl(Duration::from_millis(1));
        p.guardar_pin("9876");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(p.pin_cacheado(), None);
    }
}
