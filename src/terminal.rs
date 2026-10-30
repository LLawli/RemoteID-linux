//! Os subcomandos de terminal.

use std::io::BufRead;

use gtk::glib::ExitCode;
use remoteid::caminhos::{self, Caminhos};
use remoteid::motor::Motor;
use remoteid::protocolo::requisicao::Maquina;
use remoteid::transporte::{Http, TEMPO_LIMITE};

pub const ENTRAR: &str = "entrar";

/// `remoteid entrar <email>`: entra na conta, registra esta máquina e baixa a
/// carteira. A senha vem pelo stdin, nunca por argumento.
pub fn entrar(args: &[String]) -> ExitCode {
    let [email] = args else {
        eprintln!("uso: remoteid entrar <email>  (senha pelo stdin)");
        return ExitCode::FAILURE;
    };
    let mut senha = String::new();
    if std::io::stdin().lock().read_line(&mut senha).is_err() {
        return ExitCode::FAILURE;
    }
    let maquina_nome = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    let usuario = std::env::var("USER").unwrap_or_default();
    let maquina = Maquina {
        nome: &maquina_nome,
        usuario_local: &usuario,
        dominio_rede: &maquina_nome,
    };
    let resultado = Motor::abrir(
        Caminhos::do_ambiente(),
        caminhos::servidor(),
        Box::new(Http::novo(TEMPO_LIMITE)),
    )
    .and_then(|mut motor| motor.preparar(email, senha.trim_end_matches(['\r', '\n']), &maquina));
    match resultado {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:?}");
            ExitCode::FAILURE
        }
    }
}
