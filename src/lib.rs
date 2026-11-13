//! O núcleo do RemoteID e o módulo PKCS#11 que o p11-kit carrega.
//!
//! Não depende de GTK: o mesmo código vira o `libremoteid.so`, que roda dentro
//! do `p11-kit server` do Âncora, e o binário `remoteid`, que tem a janela.

use std::sync::OnceLock;

pub mod cadeia;
pub mod cades;
pub mod caminhos;
pub mod carteira;
pub mod cofre;
pub mod cripto;
pub mod diagnostico;
pub mod estado;
pub mod harness;
pub mod motor;
pub mod pedido;
pub mod pin;
pub mod pkcs11;
pub mod protocolo;
pub mod servico;
pub mod transporte;
pub mod x509;

/// O ref da extensão no Âncora, o mesmo do manifesto e do metainfo.
pub const APP_ID: &str = "dev.lukakuuhaku.Ancora.Driver.RemoteID";

/// O que vem depois do id do aplicativo que hospeda a extensão.
const SUFIXO_DO_ID: &str = ".Driver.RemoteID";

pub const NOME: &str = "RemoteID";

/// O id do aplicativo GTK e do item no chaveiro. O Flatpak só deixa o sandbox
/// ser dono de nomes D-Bus abaixo do id do aplicativo dele, então o id sai do
/// hospedeiro: no Âncora, é o [`APP_ID`].
pub fn id_do_aplicativo() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| id_no_hospedeiro(std::env::var("FLATPAK_ID").ok().as_deref()))
}

fn id_no_hospedeiro(hospedeiro: Option<&str>) -> String {
    match hospedeiro {
        Some(id) if !id.is_empty() => format!("{id}{SUFIXO_DO_ID}"),
        _ => APP_ID.to_string(),
    }
}

/// O nome desta máquina e o usuário local, como o registro os manda à
/// Certisign.
pub fn desta_maquina() -> (String, String) {
    let nome = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    (nome, std::env::var("USER").unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_ancora_o_id_nao_muda() {
        assert_eq!(
            id_no_hospedeiro(Some("dev.lukakuuhaku.Ancora")),
            "dev.lukakuuhaku.Ancora.Driver.RemoteID"
        );
    }

    #[test]
    fn em_outro_hospedeiro_o_id_fica_abaixo_do_dele() {
        assert_eq!(
            id_no_hospedeiro(Some("io.github.pedrohqb.Tessera")),
            "io.github.pedrohqb.Tessera.Driver.RemoteID"
        );
    }

    #[test]
    fn fora_do_flatpak_vale_o_ref() {
        assert_eq!(id_no_hospedeiro(None), APP_ID);
        assert_eq!(id_no_hospedeiro(Some("")), APP_ID);
    }
}
