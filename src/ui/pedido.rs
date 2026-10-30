//! `remoteid pedir`: o diálogo de PIN e OTP que o módulo PKCS#11 abre no meio
//! de uma assinatura. Lê o [`Pedido`] do stdin, escreve os [`Fatores`] no
//! stdout e sai com 0; fechar a janela sai com 1, e o módulo entende como
//! desistência.

use std::cell::Cell;
use std::io::Write;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use remoteid::motor::Fatores;
use remoteid::pedido::Pedido;
use remoteid::{APP_ID, NOME};

pub fn executar() -> glib::ExitCode {
    let pedido: Pedido = serde_json::from_reader(std::io::stdin()).unwrap_or_default();
    // Outra instância do id (a janela aberta) não pode receber esta pergunta.
    let app = adw::Application::builder()
        .application_id(APP_ID)
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
    // O CN do titular é `NOME:CPF`; o CPF não precisa estar na tela.
    let titular = pedido
        .titular
        .as_deref()
        .map(|t| t.split(':').next().unwrap_or(t))
        .unwrap_or(NOME);

    let pin = adw::PasswordEntryRow::builder().title("PIN").build();
    let otp = adw::EntryRow::builder()
        .title("OTP")
        .input_purpose(gtk::InputPurpose::Digits)
        .build();
    let campos = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    campos.append(&pin);
    campos.append(&otp);

    let assinar = gtk::Button::builder()
        .label("Assinar")
        .css_classes(["suggested-action", "pill"])
        .halign(gtk::Align::Center)
        .sensitive(false)
        .build();

    let corpo = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(24)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    corpo.append(&campos);
    corpo.append(&assinar);

    let conteudo = adw::ToolbarView::new();
    conteudo.add_top_bar(
        &adw::HeaderBar::builder()
            .title_widget(&adw::WindowTitle::new(titular, NOME))
            .build(),
    );
    if let Some(recusa) = &pedido.recusa {
        conteudo.add_top_bar(&adw::Banner::builder().title(recusa).revealed(true).build());
    }
    conteudo.set_content(Some(&corpo));

    let janela = adw::ApplicationWindow::builder()
        .application(app)
        .title(NOME)
        .default_width(380)
        .resizable(false)
        .content(&conteudo)
        .build();

    let completo = {
        let (pin, otp) = (pin.clone(), otp.clone());
        move || !pin.text().is_empty() && !otp.text().is_empty()
    };
    let atualizar = {
        let (assinar, completo) = (assinar.clone(), completo.clone());
        move || assinar.set_sensitive(completo())
    };
    pin.connect_changed({
        let atualizar = atualizar.clone();
        move |_| atualizar()
    });
    otp.connect_changed(move |_| atualizar());

    let responder = {
        let (pin, otp, janela) = (pin.clone(), otp.clone(), janela.clone());
        move || {
            if !completo() {
                return;
            }
            let fatores = Fatores {
                pin: pin.text().into(),
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
    pin.connect_entry_activated({
        let otp = otp.clone();
        move |_| {
            otp.grab_focus();
        }
    });
    otp.connect_entry_activated(move |_| responder());

    janela.present();
    pin.grab_focus();
}
