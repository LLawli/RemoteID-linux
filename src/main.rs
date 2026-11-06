mod terminal;
mod ui;

use adw::prelude::*;
use remoteid::{id_do_aplicativo, pedido};

fn main() -> gtk::glib::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(pedido::SUBCOMANDO) => ui::pedido::executar(),
        Some(terminal::ENTRAR) => terminal::entrar(&args[1..]),
        Some(terminal::ASSINAR) => terminal::assinar(&args[1..]),
        Some(terminal::HARNESS) => terminal::harness(&args[1..]),
        _ => janela(),
    }
}

fn janela() -> gtk::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id(id_do_aplicativo())
        .build();
    app.connect_activate(ui::janela::abrir);
    app.run_with_args::<&str>(&[])
}
