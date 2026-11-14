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
    let executar: fn(&[String]) -> ExitCode = match comando {
        #[cfg(feature = "janela")]
        pedido::SUBCOMANDO => return ui::pedido::executar(),
        terminal::AJUDA | "--help" | "-h" => return terminal::ajuda(),
        terminal::ENTRAR => terminal::entrar,
        terminal::ASSINAR => terminal::assinar,
        terminal::HARNESS => terminal::harness,
        terminal::DIAGNOSTICO => terminal::diagnostico,
        terminal::ESTADO => terminal::estado,
        terminal::ATUALIZAR => terminal::atualizar,
        terminal::USAR => terminal::usar,
        terminal::REAUTORIZAR => terminal::reautorizar,
        terminal::SAIR => terminal::sair,
        terminal::SERVIR => terminal::servir,
        _ => return sem_comando(),
    };
    // Antes de qualquer segredo: sem a proteção, o comando não roda.
    if let Err(e) = terminal::proteger_processo() {
        eprintln!("remoteid: não protegeu a memória do processo: {e}");
        return ExitCode::FAILURE;
    }
    executar(resto)
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

/// Sem a janela, o que não é um comando mostra os comandos e falha.
#[cfg(not(feature = "janela"))]
fn sem_comando() -> ExitCode {
    let _ = terminal::ajuda();
    ExitCode::FAILURE
}
