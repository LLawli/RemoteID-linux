//! Modo `--preview`: instanciação paralela de todas as telas com dados mock.
//!
//! Abre uma janela independente para cada tela da aplicação simultaneamente,
//! permitindo a inspeção visual rápida de todos os estados sem inicializar
//! motor de criptografia, persistência em disco ou sockets.

use adw::prelude::*;

use crate::telas::{configuracoes, login, painel, pin_otp, selecao};

/// Inicializa e apresenta todas as telas da aplicação em janelas simultâneas.
pub fn construir_preview(app: &adw::Application) {
    println!("[PREVIEW] Inicializando janelas de preview simultâneas...");

    // 1. Tela de Login / Instalação
    let j_login = login::criar_janela_preview();
    j_login.set_application(Some(app));
    j_login.present();

    // 2. Painel Inicial (Instalação preparada)
    let j_painel = painel::criar_janela_preview();
    j_painel.set_application(Some(app));
    j_painel.present();

    // 3. Seleção de Certificado
    let j_selecao = selecao::criar_janela_preview();
    j_selecao.set_application(Some(app));
    j_selecao.present();

    // 4. Configurações
    let j_config = configuracoes::criar_janela_preview();
    j_config.set_application(Some(app));
    j_config.present();

    // 5. Diálogo PIN / OTP (com mock de titular e hospedeiro Papers)
    let j_pin_otp = pin_otp::criar_janela_preview("MARIA SILVA:12345678900", "GNOME Papers");
    j_pin_otp.set_application(Some(app));
    j_pin_otp.present();

    println!("[PREVIEW] 5 janelas de validação abertas.");
}
