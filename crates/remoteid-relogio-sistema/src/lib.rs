//! Adaptador de relógio: o relógio do sistema. Implementa [`remoteid_portas::Relogio`].
//!
//! Existe para o núcleo ser determinístico e testável: o pré-filtro do cache do
//! `sessionToken` decide pelo tempo, e nos testes um relógio fixo substitui este.

use std::time::{SystemTime, UNIX_EPOCH};

use remoteid_portas::Relogio;

pub struct RelogioSistema;

impl Relogio for RelogioSistema {
    fn agora(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agora_avanca_e_e_plausivel() {
        // Depois de 2020 (1577836800) e determinístico o suficiente para um teste.
        assert!(RelogioSistema.agora() > 1_577_836_800);
    }
}
