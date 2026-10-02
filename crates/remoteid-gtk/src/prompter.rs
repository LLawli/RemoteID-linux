//! Implementação do trait `Prompter` via interface GTK4 com cache de PIN em memória.
//!
//! O `GtkPrompter` gerencia o tempo de vida do PIN em memória (TTL configurável)
//! e delega ao diálogo modal (`crate::telas::pin_otp`) a coleta dos fatores.
//!
//! O cache só guarda PIN que o servidor ACEITOU. O PIN do diálogo fica pendente
//! até o veredito do `tokensessao` ([`Prompter::confirmar`]): aceito, vira
//! cache; recusado, some junto com o que havia no cache. Antes da issue 21 o
//! PIN entrava no cache ao sair do diálogo, e um PIN errado voltava preenchido
//! (com o foco já no OTP) em cada assinatura dos 5 minutos seguintes, gastando
//! tentativas em nome do titular sem que ele visse o campo.
//! Como `Prompter` exige `Send + Sync`, a estrutura armazena apenas tipos seguros
//! para concorrência (`RwLock`, `Duration`), e os objetos de interface nascem
//! e morrem na thread principal durante o loop do diálogo.

use std::sync::{Mutex, RwLock};
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
    /// PIN do último diálogo, esperando o veredito do servidor.
    pendente: Mutex<Option<String>>,
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
            pendente: Mutex::new(None),
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

    /// Limpa o cache de PIN em memória imediatamente, e o PIN pendente junto.
    pub fn limpar_cache(&self) {
        if let Ok(mut guarda) = self.cache_pin.write() {
            *guarda = None;
        }
        if let Ok(mut guarda) = self.pendente.lock() {
            *guarda = None;
        }
    }

    /// O PIN com que o diálogo abre. Numa nova tentativa depois de uma recusa,
    /// nenhum: o PIN pode ser justamente o que estava errado, e só o titular
    /// digitando de novo decide gastar outra tentativa com ele.
    fn pin_inicial(&self, contexto: &Contexto) -> Option<String> {
        if contexto.recusa_anterior.is_some() {
            return None;
        }
        self.pin_cacheado()
    }

    /// Guarda o PIN do diálogo até o veredito do servidor.
    fn registrar_pendente(&self, pin: &str) {
        if let Ok(mut guarda) = self.pendente.lock() {
            *guarda = Some(pin.to_string());
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
        let pin_inicial = self.pin_inicial(contexto);

        // Localiza a janela ativa da aplicação para ancorar o diálogo modal flutuante
        let janela_pai = gtk::gio::Application::default()
            .and_downcast::<gtk::Application>()
            .and_then(|app| app.active_window())
            // Com a janela fechada ela só está escondida (o app se mantém no
            // ar, issue 26), e o `active_window()` continua devolvendo ela.
            // Ancorar o diálogo numa janela invisível arrisca escondê-lo
            // junto; sem pai ele aparece sozinho, como quando o app está atrás.
            .filter(|janela| janela.is_visible());

        let resultado = crate::telas::pin_otp::rodar_modal(
            janela_pai.as_ref(),
            contexto.titular.as_deref(),
            contexto.hospedeiro.as_deref(),
            pin_inicial.as_deref(),
            contexto.recusa_anterior.as_deref(),
        )?;

        if let Fatores::PinOtp { ref pin, .. } = resultado {
            self.registrar_pendente(pin);
        }

        Ok(resultado)
    }

    fn confirmar(&self, aceitos: bool) {
        let pendente = self.pendente.lock().ok().and_then(|mut g| g.take());
        if aceitos {
            if let Some(pin) = pendente {
                self.guardar_pin(&pin);
            }
        } else {
            // O servidor não diz se errou o PIN ou o OTP. Na dúvida, o PIN
            // do cache também sai: é o que impede reenviá-lo sem o titular ver.
            self.limpar_cache();
        }
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

    fn recusado() -> Contexto {
        Contexto {
            recusa_anterior: Some("PIN ou e-Token incorreto".into()),
            ..Contexto::default()
        }
    }

    #[test]
    fn pin_so_vira_cache_depois_de_aceito() {
        let p = GtkPrompter::com_ttl(Duration::from_secs(60));
        p.registrar_pendente("9876");
        assert_eq!(p.pin_cacheado(), None, "antes do veredito não há cache");
        p.confirmar(true);
        assert_eq!(p.pin_cacheado().as_deref(), Some("9876"));
    }

    #[test]
    fn recusa_descarta_o_pendente_e_o_cache() {
        // O cenário da issue 21: um PIN aceito antes, e depois uma recusa.
        // Nenhum dos dois pode voltar preenchido.
        let p = GtkPrompter::com_ttl(Duration::from_secs(60));
        p.registrar_pendente("1111");
        p.confirmar(true);
        p.registrar_pendente("2222");
        p.confirmar(false);
        assert_eq!(p.pin_cacheado(), None);
        assert_eq!(p.pin_inicial(&Contexto::default()), None);
        // E um veredito atrasado não ressuscita o pendente descartado.
        p.confirmar(true);
        assert_eq!(p.pin_cacheado(), None);
    }

    #[test]
    fn nova_tentativa_nunca_abre_com_pin_preenchido() {
        // Mesmo que algo tenha sobrado no cache, o diálogo de uma nova
        // tentativa abre com o PIN vazio.
        let p = GtkPrompter::com_ttl(Duration::from_secs(60));
        p.guardar_pin("9876");
        assert_eq!(p.pin_inicial(&recusado()), None);
        assert_eq!(p.pin_inicial(&Contexto::default()).as_deref(), Some("9876"));
    }

    #[test]
    fn expira_quando_passado_o_ttl() {
        let p = GtkPrompter::com_ttl(Duration::from_millis(1));
        p.guardar_pin("9876");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(p.pin_cacheado(), None);
    }
}
