//! Os subcomandos de terminal.

use std::io::BufRead;

use gtk::glib::ExitCode;
use remoteid::caminhos::{self, Caminhos};
use remoteid::cofre;
use remoteid::diagnostico::Diagnostico;
use remoteid::motor::Motor;
use remoteid::pin;
use remoteid::protocolo::requisicao::Maquina;
use remoteid::transporte::{Http, TEMPO_LIMITE};
use zeroize::Zeroizing;

pub const ENTRAR: &str = "entrar";

/// `remoteid entrar <email>`: entra na conta, registra esta máquina e baixa a
/// carteira. A senha vem pelo stdin, nunca por argumento. Sem chaveiro no
/// sistema, a segunda linha é o PIN local que vai proteger a senha
/// ([`remoteid::pin`]); sem ela, a senha é pedida a cada sessão.
pub fn entrar(args: &[String]) -> ExitCode {
    let [email] = args else {
        eprintln!(
            "uso: remoteid entrar <email>  (senha pelo stdin; sem chaveiro, o PIN na linha seguinte)"
        );
        return ExitCode::FAILURE;
    };
    let mut entrada = std::io::stdin().lock();
    let mut senha = Zeroizing::new(String::new());
    if entrada.read_line(&mut senha).is_err() {
        return ExitCode::FAILURE;
    }
    let senha = senha.trim_end_matches(['\r', '\n']);
    let (maquina_nome, usuario) = desta_maquina();
    let maquina = Maquina {
        nome: &maquina_nome,
        usuario_local: &usuario,
        dominio_rede: &maquina_nome,
    };
    let caminhos = Caminhos::do_ambiente();
    let mut motor = match Motor::abrir(
        caminhos.clone(),
        caminhos::servidor(),
        Box::new(Http::novo(TEMPO_LIMITE)),
    ) {
        Ok(motor) => motor
            .com_cofre(cofre::do_ambiente())
            .com_diagnostico(Diagnostico::abrir(&caminhos.diagnostico())),
        Err(e) => {
            eprintln!("{e:?}");
            return ExitCode::FAILURE;
        }
    };
    match motor.preparar(email, senha, &maquina) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            let mut pin = Zeroizing::new(String::new());
            let _ = entrada.read_line(&mut pin);
            let pin = pin.trim();
            if !pin::valido(pin) {
                eprintln!(
                    "sem chaveiro no sistema e sem um PIN de {} a {} dígitos: a senha será pedida a cada sessão",
                    pin::MIN_DIGITOS,
                    pin::MAX_DIGITOS
                );
                return ExitCode::SUCCESS;
            }
            match motor.proteger_com_pin(senha, pin) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e:?}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("{e:?}");
            ExitCode::FAILURE
        }
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
