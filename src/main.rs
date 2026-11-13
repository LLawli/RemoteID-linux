mod terminal;
#[cfg(feature = "janela")]
mod ui;

use std::process::ExitCode;

#[cfg(feature = "janela")]
use adw::prelude::*;
#[cfg(feature = "janela")]
use remoteid::{id_do_aplicativo, pedido};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(comando) = args.first().map(String::as_str) else {
        return sem_comando();
    };
    let resto = &args[1..];
    match comando {
        #[cfg(feature = "janela")]
        pedido::SUBCOMANDO => ui::pedido::executar(),
        terminal::ENTRAR => terminal::entrar(resto),
        terminal::ASSINAR => terminal::assinar(resto),
        terminal::HARNESS => terminal::harness(resto),
        terminal::DIAGNOSTICO => terminal::diagnostico(resto),
        terminal::ESTADO => terminal::estado(resto),
        terminal::ATUALIZAR => terminal::atualizar(resto),
        terminal::USAR => terminal::usar(resto),
        terminal::REAUTORIZAR => terminal::reautorizar(resto),
        terminal::SAIR => terminal::sair(resto),
        terminal::SERVIR => terminal::servir(resto),
        terminal::AJUDA | "--help" | "-h" => terminal::ajuda(),
        _ => sem_comando(),
    }
}

#[cfg(feature = "janela")]
fn sem_comando() -> ExitCode {
    let app = adw::Application::builder()
        .application_id(id_do_aplicativo())
        .build();
    app.connect_activate(ui::janela::abrir);
    if app.run_with_args::<&str>(&[]) == gtk::glib::ExitCode::SUCCESS {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Sem a janela, o que não é um comando mostra os comandos.
#[cfg(not(feature = "janela"))]
fn sem_comando() -> ExitCode {
    terminal::ajuda();
    ExitCode::FAILURE
}
