//! As telas GTK4 do RemoteID-linux, como funções reutilizáveis.
//!
//! Cada tela é uma função que recebe um **modelo plano** ([`modelo`]) e
//! devolve um widget, sem tocar em socket nem no protocolo. Isso permite dois
//! consumidores da MESMA tela, sem divergência:
//!
//! 1. o binário `remoteid-gtk` (a janela principal e o modo `--preview`);
//! 2. o **daemon** (`remoteid-daemon`), que reusa [`telas::pin_otp`] para
//!    mostrar exatamente o diálogo de PIN/OTP que o usuário validou no preview.
//!
//! Por isso esta lib não depende do daemon (seria ciclo) nem do protocolo: a
//! ponte entre o `SucessoResposta::Status` do protocolo e o [`modelo::EstadoApp`]
//! é feita no binário (`main.rs`), não aqui.

pub mod modelo;
pub mod telas;
