//! O núcleo do RemoteID e o módulo PKCS#11 que o p11-kit carrega.
//!
//! Não depende de GTK: o mesmo código vira o `libremoteid.so`, que roda dentro
//! do `p11-kit server` do Âncora, e o binário `remoteid`, que tem a janela.

pub mod cadeia;
pub mod caminhos;
pub mod carteira;
pub mod cofre;
pub mod cripto;
pub mod diagnostico;
pub mod estado;
pub mod motor;
pub mod pedido;
pub mod pin;
pub mod pkcs11;
pub mod protocolo;
pub mod transporte;
pub mod x509;

/// O ref da extensão. É também o id do aplicativo GTK: o Flatpak deixa o
/// sandbox do Âncora ser dono de nomes D-Bus abaixo de `dev.lukakuuhaku.Ancora`.
pub const APP_ID: &str = "dev.lukakuuhaku.Ancora.Driver.RemoteID";

pub const NOME: &str = "RemoteID";
