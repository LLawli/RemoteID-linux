//! Tela 1: Login / Instalação inicial (quando a aplicação não está preparada).
//!
//! Exibe uma página de boas-vindas com orientações e coleta de credenciais
//! do RemoteID (e-mail e senha) para registrar o desktop e baixar os certificados.

use std::rc::Rc;

use adw::prelude::*;

/// Ações disponíveis na tela de login.
#[derive(Clone)]
pub struct AcoesLogin {
    /// Disparada ao clicar em "Preparar instalação" com (email, senha).
    pub preparar: Rc<dyn Fn(String, String)>,
}

/// Monta o widget da tela de login seguindo o GNOME HIG e libadwaita.
pub fn montar(acoes: AcoesLogin) -> gtk::Widget {
    let clamp = adw::Clamp::builder()
        .maximum_size(420)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(16)
        .margin_end(16)
        .build();

    let caixa_form = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .build();

    let grupo_credenciais = adw::PreferencesGroup::new();
    let campo_email = adw::EntryRow::builder().title("E-mail do RemoteID").build();
    campo_email.set_input_purpose(gtk::InputPurpose::Email);

    let campo_senha = adw::PasswordEntryRow::builder().title("Senha").build();

    grupo_credenciais.add(&campo_email);
    grupo_credenciais.add(&campo_senha);
    caixa_form.append(&grupo_credenciais);

    let spinner = gtk::Spinner::builder()
        .spinning(false)
        .visible(false)
        .halign(gtk::Align::Center)
        .build();

    let rotulo_status = gtk::Label::builder()
        .halign(gtk::Align::Center)
        .visible(false)
        .wrap(true)
        .css_classes(["dim-label"])
        .build();

    let botao_preparar = gtk::Button::builder()
        .label("Preparar instalação")
        .halign(gtk::Align::Center)
        .css_classes(["pill", "suggested-action"])
        .sensitive(false)
        .margin_top(8)
        .build();

    caixa_form.append(&spinner);
    caixa_form.append(&rotulo_status);
    caixa_form.append(&botao_preparar);
    clamp.set_child(Some(&caixa_form));

    let pagina_status = adw::StatusPage::builder()
        .icon_name("dialog-password-symbolic")
        .title("Bem-vindo ao RemoteID")
        .description(
            "Configure sua conta Certisign com token RemoteID para emitir assinaturas digitais neste computador.",
        )
        .child(&clamp)
        .build();

    // Validação reativa dos campos
    let checar_preenchimento = {
        let btn = botao_preparar.clone();
        let email = campo_email.clone();
        let senha = campo_senha.clone();
        move || {
            let email_ok = !email.text().trim().is_empty();
            let senha_ok = !senha.text().trim().is_empty();
            btn.set_sensitive(email_ok && senha_ok);
        }
    };

    checar_preenchimento();
    {
        let cb = checar_preenchimento.clone();
        campo_email.connect_changed(move |_| cb());
    }
    {
        let cb = checar_preenchimento;
        campo_senha.connect_changed(move |_| cb());
    }

    // Ação do botão "Preparar instalação"
    {
        let acoes = acoes.clone();
        let btn = botao_preparar.clone();
        let spin = spinner;
        let rot = rotulo_status;
        let email_entry = campo_email;
        let senha_entry = campo_senha;

        botao_preparar.connect_clicked(move |_| {
            let email = email_entry.text().trim().to_string();
            let senha = senha_entry.text().to_string();

            btn.set_sensitive(false);
            spin.set_visible(true);
            spin.set_spinning(true);
            rot.set_visible(true);
            rot.set_text("Preparando instalação com o servidor...");

            (acoes.preparar)(email, senha);
        });
    }

    pagina_status.upcast::<gtk::Widget>()
}

/// Cria uma janela de preview para validação estática.
pub fn criar_janela_preview() -> gtk::Window {
    let acoes = AcoesLogin {
        preparar: Rc::new(|email, _| {
            println!("[PREVIEW] Login: Preparar clicado com e-mail: {email}");
        }),
    };

    let janela = adw::Window::builder()
        .title("Preview: Login / Instalação")
        .default_width(480)
        .default_height(600)
        .content(&montar(acoes))
        .build();

    janela.upcast::<gtk::Window>()
}
