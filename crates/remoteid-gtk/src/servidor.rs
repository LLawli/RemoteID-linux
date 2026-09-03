//! O servidor do socket UNIX, integrado ao loop principal do GTK.
//!
//! Unificação de 03/09/2026 ([[remoteid-app-unificado]]): não há mais daemon
//! separado. O app abre o socket ao iniciar (janela aberta) e o fecha ao sair.
//! O único cliente externo é o módulo PKCS#11 (verbo `Sign`); a própria janela
//! NÃO usa o socket — chama o [`Servico`] direto, no mesmo processo.
//!
//! Tudo roda na thread principal: o listener não-bloqueante é vigiado por um
//! watch de FD do glib, e cada conexão é atendida sincronamente. Quando um
//! `Sign` precisa de PIN/OTP, o `Servico` chama o `GtkPrompter`, que abre um
//! diálogo modal (loop aninhado) SOBRE a janela — o que bloqueia a janela e
//! evita reentrância no `Servico`. Como salvaguarda extra, se o `Servico` já
//! estiver emprestado (assinatura em curso), respondemos "ocupado" em vez de
//! reentrar.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use gtk::glib;

use remoteid_daemon::protocolo::{CodigoErro, Requisicao, Resposta};
use remoteid_daemon::servico::Servico;
use remoteid_daemon::socket;

/// Abre o socket em `caminho` e liga o watch no loop do glib. Devolve o
/// caminho, para o app limpar ao sair. O caminho vem do app: em modo normal é
/// [`socket::caminho_padrao`], em modo de teste é o de `/tmp`.
pub fn iniciar(servico: Rc<RefCell<Servico>>, caminho: PathBuf) -> Result<PathBuf, String> {
    // O app é dono do socket enquanto está aberto. Um socket sobrando de uma
    // execução anterior que morreu sem limpar bloquearia o `bind_manual`,
    // então removemos o arquivo antes. Só há uma instância do app
    // (GtkApplication é single-instance), então isto não pisa em outro
    // processo vivo.
    let _ = std::fs::remove_file(&caminho);
    let listener = socket::bind_manual(&caminho).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let fd = listener.as_raw_fd();
    let listener = Rc::new(listener);
    glib::unix_fd_add_local(fd, glib::IOCondition::IN, move |_, _| {
        // Aceita tudo que estiver pendente; cada conexão, uma mensagem/resposta.
        loop {
            match listener.accept() {
                Ok((fluxo, _)) => atender(&servico, fluxo),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        glib::ControlFlow::Continue
    });
    Ok(caminho)
}

/// Remove o arquivo do socket (chamado no shutdown do app).
pub fn limpar(caminho: &std::path::Path) {
    let _ = std::fs::remove_file(caminho);
}

fn atender(servico: &Rc<RefCell<Servico>>, fluxo: UnixStream) {
    // Timeout de leitura para um cliente que abriu e não falou não travar o
    // loop principal.
    let _ = fluxo.set_read_timeout(Some(Duration::from_secs(5)));
    let leitor_fluxo = match fluxo.try_clone() {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut leitor = BufReader::new(leitor_fluxo);
    let mut escritor = fluxo;
    let mut linha = String::new();
    if leitor.read_line(&mut linha).unwrap_or(0) == 0 {
        return;
    }

    let resposta = match serde_json::from_str::<Requisicao>(linha.trim_end()) {
        Ok(req) => match servico.try_borrow_mut() {
            Ok(mut s) => s.tratar(req),
            // Uma assinatura já está em curso (o diálogo modal está aberto).
            // Recusar é melhor que reentrar no Servico (double-borrow = panic);
            // o módulo pode repetir depois.
            Err(_) => Resposta::falha(
                CodigoErro::ErroInterno,
                "ocupado: uma autorização já está em andamento",
            ),
        },
        Err(e) => Resposta::falha(CodigoErro::RequisicaoInvalida, format!("JSON inválido: {e}")),
    };

    if let Ok(mut txt) = serde_json::to_string(&resposta) {
        txt.push('\n');
        let _ = escritor.write_all(txt.as_bytes());
        let _ = escritor.flush();
    }
}
