//! Fachada de I/O da chave da instalação: delega ao adaptador `chave-pem`.
//!
//! A leitura/geração do `installation-key.pem` mora no adaptador
//! [`remoteid_chave_pem`] (que implementa a porta `CofreDeChave`). Aqui só
//! re-exportamos as funções de baixo nível que o motor ainda chama direto. Na
//! Fase 3 o motor passa a receber um `Box<dyn CofreDeChave>` e esta fachada some.

pub use remoteid_chave_pem::{carregar, carregar_ou_gerar};
