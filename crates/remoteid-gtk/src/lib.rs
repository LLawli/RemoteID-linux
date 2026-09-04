//! Crate `remoteid-gtk`: interface gráfica em GTK4 + Libadwaita e servidor de socket in-process.
//!
//! Reúne as telas GNOME HIG, o adaptador `Prompter` com diálogo modal flutuante,
//! o loop de eventos não-bloqueante para atendimento do socket PKCS#11 e o modo `--preview`.

pub mod app;
pub mod modelo;
pub mod preview;
pub mod prompter;
pub mod telas;
