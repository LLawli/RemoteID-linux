//! `remoteid pedir`: o diálogo que o módulo PKCS#11 abre no meio de uma
//! assinatura, quando a sessão em cache não vale mais. Pede o código do
//! autenticador e, conforme a [`remoteid::motor::Credencial`], o PIN local
//! (a senha está no arquivo cifrado) ou a senha da conta (não há uma
//! guardada, ou o servidor recusou a tentativa). Lê o [`Pedido`] do stdin, escreve os [`Fatores`] no
//! stdout e sai com 0; fechar a janela sai com 1, e o módulo entende como
//! desistência.

use std::cell::Cell;
use std::io::Write;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use remoteid::carteira;
use remoteid::motor::Fatores;
use remoteid::pedido::Pedido;
use remoteid::{NOME, id_do_aplicativo};

use super::{cartao, estilo};

pub fn executar() -> glib::ExitCode {
    let pedido: Pedido = serde_json::from_reader(std::io::stdin()).unwrap_or_default();
    // Outra instância do id (a janela aberta) não pode receber esta pergunta.
    let app = adw::Application::builder()
        .application_id(id_do_aplicativo())
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let respondido = Rc::new(Cell::new(false));
    let r = respondido.clone();
    app.connect_activate(move |app| montar(app, &pedido, r.clone()));
    app.run_with_args::<&str>(&[]);
    if respondido.get() {
        glib::ExitCode::SUCCESS
    } else {
        glib::ExitCode::FAILURE
    }
}

fn montar(app: &adw::Application, pedido: &Pedido, respondido: Rc<Cell<bool>>) {
    estilo::instalar();
    let (nome, documento) = pedido
        .titular
        .as_deref()
        .map(carteira::titular)
        .unwrap_or_else(|| (NOME.into(), None));

    let senha = adw::PasswordEntryRow::builder()
        .title("Senha")
        .visible(pedido.pedir_senha)
        .build();
    senha.add_prefix(&gtk::Image::from_icon_name("dialog-password-symbolic"));
    if let Some(atual) = &pedido.senha_atual {
        senha.set_text(atual);
    }
    let pin = adw::PasswordEntryRow::builder()
        .title("PIN")
        .input_purpose(gtk::InputPurpose::Pin)
        .visible(pedido.pedir_pin)
        .build();
    pin.add_prefix(&gtk::Image::from_icon_name("system-lock-screen-symbolic"));
    let otp = adw::EntryRow::builder()
        .title("OTP")
        .input_purpose(gtk::InputPurpose::Digits)
        .build();
    otp.add_prefix(&gtk::Image::from_icon_name("phone-symbolic"));
    if pedido.recusa.is_some() {
        senha.add_css_class("error");
        pin.add_css_class("error");
        otp.add_css_class("error");
    }
    let campos = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    campos.append(&senha);
    campos.append(&pin);
    campos.append(&otp);

    let assinar = gtk::Button::builder()
        .halign(gtk::Align::Center)
        .sensitive(false)
        .css_classes(["suggested-action", "pill"])
        .child(
            &adw::ButtonContent::builder()
                .icon_name("document-edit-symbolic")
                .label("Assinar")
                .build(),
        )
        .build();

    let corpo = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(20)
        .margin_top(8)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    corpo.append(&cartao::mini(
        &nome,
        &cartao::tipo(documento.as_ref()),
        0,
        None,
    ));
    corpo.append(&campos);
    corpo.append(&assinar);

    let conteudo = adw::ToolbarView::builder()
        .top_bar_style(adw::ToolbarStyle::Flat)
        .content(&corpo)
        .build();
    conteudo.add_top_bar(&adw::HeaderBar::builder().show_title(false).build());
    if let Some(recusa) = &pedido.recusa {
        conteudo.add_top_bar(&adw::Banner::builder().title(recusa).revealed(true).build());
    }

    let janela = adw::ApplicationWindow::builder()
        .application(app)
        .title(NOME)
        .default_width(400)
        .resizable(false)
        .content(&conteudo)
        .build();

    let (pedir_senha, pedir_pin) = (pedido.pedir_senha, pedido.pedir_pin);
    let completo = {
        let (senha, pin, otp) = (senha.clone(), pin.clone(), otp.clone());
        move || {
            !otp.text().is_empty()
                && (!pedir_senha || !senha.text().is_empty())
                && (!pedir_pin || remoteid::pin::valido(&pin.text()))
        }
    };
    let atualizar = {
        let (assinar, completo) = (assinar.clone(), completo.clone());
        let (senha, pin, otp) = (senha.clone(), pin.clone(), otp.clone());
        move || {
            assinar.set_sensitive(completo());
            senha.remove_css_class("error");
            pin.remove_css_class("error");
            otp.remove_css_class("error");
        }
    };
    for campo in [
        senha.upcast_ref::<gtk::Editable>(),
        pin.upcast_ref(),
        otp.upcast_ref(),
    ] {
        let atualizar = atualizar.clone();
        campo.connect_changed(move |_| atualizar());
    }

    let responder = {
        let (senha, pin, otp, janela) = (senha.clone(), pin.clone(), otp.clone(), janela.clone());
        move || {
            if !completo() {
                return;
            }
            let fatores = Fatores {
                senha: pedir_senha.then(|| senha.text().into()),
                pin: pedir_pin.then(|| pin.text().into()),
                otp: otp.text().trim().into(),
            };
            let mut saida = std::io::stdout().lock();
            if serde_json::to_writer(&mut saida, &fatores).is_ok() && saida.flush().is_ok() {
                respondido.set(true);
            }
            janela.close();
        }
    };
    assinar.connect_clicked({
        let responder = responder.clone();
        move |_| responder()
    });
    for campo in [&senha, &pin] {
        let otp = otp.clone();
        campo.connect_entry_activated(move |_| {
            otp.grab_focus();
        });
    }
    otp.connect_entry_activated(move |_| responder());

    // Esc fecha, e fechar é desistir.
    let teclas = gtk::EventControllerKey::new();
    teclas.connect_key_pressed({
        let janela = janela.clone();
        move |_, tecla, _, _| {
            if tecla == gtk::gdk::Key::Escape {
                janela.close();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        }
    });
    janela.add_controller(teclas);

    janela.present();
    // A senha só pede o foco quando está vazia; com ela guardada, o que falta
    // é o código.
    if pedir_pin {
        pin.grab_focus();
    } else if pedir_senha && senha.text().is_empty() {
        senha.grab_focus();
    } else {
        otp.grab_focus();
    }
}
