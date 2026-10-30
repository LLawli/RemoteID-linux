//! O núcleo do RemoteID e o módulo PKCS#11 que o p11-kit carrega.
//!
//! Não depende de GTK: o mesmo código vira o `libremoteid.so`, que roda dentro
//! do `p11-kit server` do Âncora, e o binário `remoteid`, que tem a janela.

/// O ref da extensão. É também o id do aplicativo GTK: o Flatpak deixa o
/// sandbox do Âncora ser dono de nomes D-Bus abaixo de `dev.lukakuuhaku.Ancora`.
pub const APP_ID: &str = "dev.lukakuuhaku.Ancora.Driver.RemoteID";

pub const NOME: &str = "RemoteID";
