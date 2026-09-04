//! Servidor de teste: o `Servico` real com fatores FIXOS, sem GTK.
//!
//! Existe só para validar o braço de produção do `C_Sign` do módulo PKCS#11
//! (módulo → socket → Servico → mock) SEM precisar do diálogo humano de
//! PIN/OTP. É o app unificado menos a UI: mesmo `Servico`, mesmo fluxo de
//! assinatura, mas o PIN/OTP vem de `FatoresFixos` em vez do `GtkPrompter`.
//!
//! Uso (com o `remoteid-mock` no ar e a conta de teste preparada):
//!   TEST_URL=http://localhost:8799 \
//!   REMOTEID_SOCKET=/tmp/remoteid-teste/remoteid.sock \
//!   cargo run -p remoteid-daemon --example servidor-fixo

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use remoteid_daemon::prompter::FatoresFixos;
use remoteid_daemon::protocolo::{CodigoErro, Requisicao, Resposta};
use remoteid_daemon::servico::Servico;
use remoteid_daemon::socket;
use remoteid_aplicacao::Opcoes;

fn main() {
    let pin = std::env::var("FIXO_PIN").unwrap_or_else(|_| "1234".to_string());
    let otp = std::env::var("FIXO_OTP").unwrap_or_else(|_| "123456".to_string());

    // `Opcoes::default()` respeita `TEST_URL` (aponta pro mock, isola em /tmp).
    let mut servico = Servico::novo(Opcoes::default(), Box::new(FatoresFixos::novo(pin, otp)))
        .expect("abrir o motor");

    let caminho = socket::caminho_padrao();
    let _ = std::fs::remove_file(&caminho);
    let listener = socket::bind_manual(&caminho).expect("bind do socket");
    eprintln!("servidor-fixo ouvindo em {}", caminho.display());

    for conexao in listener.incoming() {
        let Ok(fluxo) = conexao else { continue };
        let _ = atender(fluxo, &mut servico);
    }
}

fn atender(fluxo: UnixStream, servico: &mut Servico) -> std::io::Result<()> {
    let mut leitor = BufReader::new(fluxo.try_clone()?);
    let mut escritor = fluxo;
    let mut linha = String::new();
    if leitor.read_line(&mut linha)? == 0 {
        return Ok(());
    }
    let resposta = match serde_json::from_str::<Requisicao>(linha.trim_end()) {
        Ok(req) => servico.tratar(req),
        Err(e) => Resposta::falha(CodigoErro::RequisicaoInvalida, format!("JSON inválido: {e}")),
    };
    let mut saida = serde_json::to_string(&resposta)?;
    saida.push('\n');
    escritor.write_all(saida.as_bytes())?;
    escritor.flush()
}
