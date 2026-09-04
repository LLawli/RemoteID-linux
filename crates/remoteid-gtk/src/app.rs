//! Ciclo de vida da aplicação GTK4, orquestrador do socket UNIX e navegação entre telas.
//!
//! Integra o servidor do socket via `glib::unix_fd_add_local` para atender o módulo
//! PKCS#11 na mesma thread da interface, mantendo a proteção contra reentrância através
//! de `try_borrow_mut` no `Servico`.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

use remoteid_aplicacao::Opcoes;
use remoteid_daemon::protocolo::{CodigoErro, Requisicao, Resposta};
use remoteid_daemon::servico::Servico;
use remoteid_daemon::socket;

use crate::modelo::{ConfigApp, EstadoApp};
use crate::prompter::GtkPrompter;
use crate::telas::{configuracoes, login, painel, selecao};

/// Tipo do serviço compartilhado entre a janela principal e o listener do socket.
pub type ServicoCompartilhado = Rc<RefCell<Servico>>;

/// Inicializa a aplicação no modo normal (janela + socket in-process).
pub fn construir_app(app: &adw::Application) {
    let teste = remoteid_caminhos::em_teste();
    let titulo = if teste {
        "RemoteID — MODO DE TESTE"
    } else {
        "RemoteID"
    };

    let janela = adw::ApplicationWindow::builder()
        .application(app)
        .title(titulo)
        .default_width(520)
        .default_height(680)
        .build();

    let opcoes = Opcoes::default();
    let prompter = Box::new(GtkPrompter::novo());

    let servico = match Servico::novo(opcoes, prompter) {
        Ok(s) => Rc::new(RefCell::new(s)),
        Err(e) => {
            let pagina_erro = adw::StatusPage::builder()
                .icon_name("dialog-error-symbolic")
                .title("Falha ao inicializar o motor")
                .description(format!("{e}\n\nA aplicação não pode continuar."))
                .build();
            janela.set_content(Some(&pagina_erro));
            janela.present();
            return;
        }
    };

    // Inicializa o servidor do socket UNIX vigiado pelo GLib
    let caminho_socket = socket::caminho_padrao();
    match iniciar_socket(servico.clone(), caminho_socket.clone()) {
        Ok(caminho) => {
            let c_limpar = caminho.clone();
            app.connect_shutdown(move |_| {
                limpar_socket(&c_limpar);
            });
        }
        Err(e) => {
            eprintln!("Aviso: Falha ao iniciar socket UNIX em {}: {e}", caminho_socket.display());
        }
    }

    // Inicializa a navegação da interface
    navegar_para_estado_atual(&janela, &servico, teste);
    janela.present();
}

/// Sobe o socket UNIX não-bloqueante e integra ao loop de eventos do GLib.
pub fn iniciar_socket(
    servico: ServicoCompartilhado,
    caminho: PathBuf,
) -> Result<PathBuf, String> {
    limpar_socket(&caminho);
    let listener = socket::bind_manual(&caminho).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let fd = listener.as_raw_fd();
    let listener = Rc::new(listener);

    glib::unix_fd_add_local(fd, glib::IOCondition::IN, move |_, _| {
        loop {
            match listener.accept() {
                Ok((fluxo, _)) => atender_conexao(&servico, fluxo),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        glib::ControlFlow::Continue
    });

    Ok(caminho)
}

/// Remove o arquivo do socket do sistema de arquivos.
pub fn limpar_socket(caminho: &Path) {
    let _ = std::fs::remove_file(caminho);
}

/// Atende uma conexão recebida no socket UNIX de maneira síncrona e segura contra reentrância.
fn atender_conexao(servico: &ServicoCompartilhado, fluxo: UnixStream) {
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
            Err(_) => Resposta::falha(
                CodigoErro::ErroInterno,
                "ocupado: uma autorização já está em andamento",
            ),
        },
        Err(e) => Resposta::falha(
            CodigoErro::RequisicaoInvalida,
            format!("JSON inválido: {e}"),
        ),
    };

    if let Ok(mut txt) = serde_json::to_string(&resposta) {
        txt.push('\n');
        let _ = escritor.write_all(txt.as_bytes());
        let _ = escritor.flush();
    }
}

/// Consulta o estado atual e renderiza a tela apropriada (Login ou Painel).
pub fn navegar_para_estado_atual(
    janela: &adw::ApplicationWindow,
    servico: &ServicoCompartilhado,
    teste: bool,
) {
    let status_resp = servico.borrow_mut().tratar(Requisicao::Status);
    let estado = match status_resp {
        Resposta::Sucesso(ref s) => EstadoApp::de_status(s).unwrap_or_else(EstadoApp::mock_nao_preparado),
        _ => EstadoApp::mock_nao_preparado(),
    };

    if !estado.preparado {
        mostrar_tela_login(janela, servico, teste);
    } else {
        mostrar_tela_painel(janela, servico, &estado, teste);
    }
}

/// Renderiza a tela de Login/Instalação.
fn mostrar_tela_login(
    janela: &adw::ApplicationWindow,
    servico: &ServicoCompartilhado,
    teste: bool,
) {
    let cabecalho = adw::HeaderBar::new();
    let subtitulo = if teste { "Modo de Teste" } else { "" };
    cabecalho.set_title_widget(Some(&adw::WindowTitle::new("RemoteID", subtitulo)));

    let j_clone = janela.clone();
    let s_clone = servico.clone();

    let acoes = login::AcoesLogin {
        preparar: Rc::new(move |email, senha| {
            let j_async = j_clone.clone();
            let s_async = s_clone.clone();

            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let resultado = preparar_via_cli(&email, &senha);
                let _ = tx.send(resultado);
            });

            glib::timeout_add_local(Duration::from_millis(100), move || {
                match rx.try_recv() {
                    Ok(resultado) => {
                        match resultado {
                            Ok(()) => {
                                if let Err(e) = s_async.borrow_mut().reabrir() {
                                    mostrar_erro(&j_async, "Instalação concluída com ressalva", &format!("O estado foi gravado, mas a recarga falhou: {e}"));
                                }
                                navegar_para_estado_atual(&j_async, &s_async, teste);
                            }
                            Err(msg) => {
                                mostrar_erro(&j_async, "Falha ao preparar instalação", &msg);
                                navegar_para_estado_atual(&j_async, &s_async, teste);
                            }
                        }
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
                }
            });
        }),
    };

    let corpo = login::montar(acoes);
    let barra = adw::ToolbarView::new();
    barra.add_top_bar(&cabecalho);
    barra.set_content(Some(&corpo));

    janela.set_content(Some(&barra));
}

/// Renderiza a tela de Painel Principal.
fn mostrar_tela_painel(
    janela: &adw::ApplicationWindow,
    servico: &ServicoCompartilhado,
    estado: &EstadoApp,
    teste: bool,
) {
    let cabecalho = adw::HeaderBar::new();
    let subtitulo = if teste { "Modo de Teste" } else { "" };
    cabecalho.set_title_widget(Some(&adw::WindowTitle::new("RemoteID", subtitulo)));

    let botao_cfg = gtk::Button::builder()
        .icon_name("preferences-system-symbolic")
        .tooltip_text("Configurações")
        .build();

    let j_cfg = janela.clone();
    let s_cfg = servico.clone();
    botao_cfg.connect_clicked(move |_| {
        mostrar_tela_configuracoes(&j_cfg, &s_cfg, teste);
    });
    cabecalho.pack_end(&botao_cfg);

    let j_painel = janela.clone();
    let s_painel = servico.clone();

    let acoes = painel::AcoesPainel {
        abrir_configuracoes: Rc::new({
            let j = janela.clone();
            let s = servico.clone();
            move || mostrar_tela_configuracoes(&j, &s, teste)
        }),
        trocar_certificado: Rc::new({
            let j = janela.clone();
            let s = servico.clone();
            move || mostrar_tela_selecao(&j, &s, teste)
        }),
        reautorizar: Rc::new(move || {
            let r = s_painel.borrow_mut().tratar(Requisicao::ReautorizarProxima);
            if let Resposta::Falha { erro, .. } = r {
                mostrar_erro(&j_painel, "Falha ao reautorizar", &erro);
            }
            navegar_para_estado_atual(&j_painel, &s_painel, teste);
        }),
    };

    let corpo = painel::montar(estado, acoes);
    let barra = adw::ToolbarView::new();
    barra.add_top_bar(&cabecalho);
    barra.set_content(Some(&corpo));

    janela.set_content(Some(&barra));
}

/// Renderiza a tela de Seleção de Certificado.
fn mostrar_tela_selecao(
    janela: &adw::ApplicationWindow,
    servico: &ServicoCompartilhado,
    teste: bool,
) {
    let status_resp = servico.borrow_mut().tratar(Requisicao::Status);
    let estado = match status_resp {
        Resposta::Sucesso(ref s) => EstadoApp::de_status(s).unwrap_or_else(EstadoApp::mock_nao_preparado),
        _ => EstadoApp::mock_nao_preparado(),
    };

    let cabecalho = adw::HeaderBar::new();
    cabecalho.set_title_widget(Some(&adw::WindowTitle::new("Selecionar Certificado", "")));

    let botao_voltar = gtk::Button::builder()
        .icon_name("go-previous-symbolic")
        .tooltip_text("Voltar")
        .build();

    let j_voltar = janela.clone();
    let s_voltar = servico.clone();
    botao_voltar.connect_clicked(move |_| {
        navegar_para_estado_atual(&j_voltar, &s_voltar, teste);
    });
    cabecalho.pack_start(&botao_voltar);

    let j_sel = janela.clone();
    let s_sel = servico.clone();

    let acoes = selecao::AcoesSelecao {
        voltar: Rc::new({
            let j = janela.clone();
            let s = servico.clone();
            move || navegar_para_estado_atual(&j, &s, teste)
        }),
        confirmar: Rc::new(move |key_name| {
            let r = s_sel.borrow_mut().tratar(Requisicao::EscolherCertificado { key_name });
            if let Resposta::Falha { erro, .. } = r {
                mostrar_erro(&j_sel, "Não foi possível alterar o certificado", &erro);
            }
            navegar_para_estado_atual(&j_sel, &s_sel, teste);
        }),
    };

    let corpo = selecao::montar(&estado, acoes);
    let barra = adw::ToolbarView::new();
    barra.add_top_bar(&cabecalho);
    barra.set_content(Some(&corpo));

    janela.set_content(Some(&barra));
}

/// Renderiza a tela de Configurações.
fn mostrar_tela_configuracoes(
    janela: &adw::ApplicationWindow,
    servico: &ServicoCompartilhado,
    teste: bool,
) {
    let status_resp = servico.borrow_mut().tratar(Requisicao::Status);
    let estado = match status_resp {
        Resposta::Sucesso(ref s) => EstadoApp::de_status(s).unwrap_or_else(EstadoApp::mock_nao_preparado),
        _ => EstadoApp::mock_nao_preparado(),
    };

    let cabecalho = adw::HeaderBar::new();
    cabecalho.set_title_widget(Some(&adw::WindowTitle::new("Configurações", "")));

    let botao_voltar = gtk::Button::builder()
        .icon_name("go-previous-symbolic")
        .tooltip_text("Voltar")
        .build();

    let j_voltar = janela.clone();
    let s_voltar = servico.clone();
    botao_voltar.connect_clicked(move |_| {
        navegar_para_estado_atual(&j_voltar, &s_voltar, teste);
    });
    cabecalho.pack_start(&botao_voltar);

    let cfg = ConfigApp {
        cache_pin_min: 5,
        ttl_sessao_min: 15,
        nome_aplicacao: "RemoteID-linux".to_string(),
        caminho_log: remoteid_caminhos::dir_diag().to_string_lossy().to_string(),
    };

    let j_cfg = janela.clone();
    let s_cfg = servico.clone();

    let acoes = configuracoes::AcoesConfiguracoes {
        voltar: Rc::new({
            let j = janela.clone();
            let s = servico.clone();
            move || navegar_para_estado_atual(&j, &s, teste)
        }),
        salvar: Rc::new({
            let j = janela.clone();
            let s = servico.clone();
            move |_nova_cfg| {
                navegar_para_estado_atual(&j, &s, teste);
            }
        }),
        trocar_certificado: if estado.certificados.len() > 1 {
            Some(Rc::new({
                let j = janela.clone();
                let s = servico.clone();
                move || mostrar_tela_selecao(&j, &s, teste)
            }))
        } else {
            None
        },
        reinstalar: Rc::new(move || {
            let r = s_cfg.borrow_mut().tratar(Requisicao::Reinstalar);
            if let Resposta::Falha { erro, .. } = r {
                mostrar_erro(&j_cfg, "Falha ao reinstalar", &erro);
            }
            navegar_para_estado_atual(&j_cfg, &s_cfg, teste);
        }),
    };

    let cert_ativo = estado.certificado_ativo_ou_primeiro();
    let multi_cert = estado.certificados.len() > 1;
    let corpo = configuracoes::montar(&cfg, cert_ativo, multi_cert, acoes);

    let barra = adw::ToolbarView::new();
    barra.add_top_bar(&cabecalho);
    barra.set_content(Some(&corpo));

    janela.set_content(Some(&barra));
}

/// Executa o comando CLI `remoteid preparar` passando credenciais via ambiente.
fn preparar_via_cli(email: &str, senha: &str) -> Result<(), String> {
    let mut cmd = match std::env::current_exe() {
        Ok(p) => {
            let vizinho = p.parent().map(|dir| dir.join("remoteid"));
            if let Some(v) = vizinho.filter(|v| v.exists()) {
                std::process::Command::new(v)
            } else {
                std::process::Command::new("remoteid")
            }
        }
        Err(_) => std::process::Command::new("remoteid"),
    };

    cmd.arg("preparar")
        .env("REMOTEID_EMAIL", email)
        .env("REMOTEID_SENHA", senha);

    if let Ok(u) = std::env::var("TEST_URL") {
        cmd.env("TEST_URL", u);
    }

    let saida = cmd
        .output()
        .map_err(|e| format!("Não foi possível executar o binário `remoteid`: {e}"))?;

    if saida.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&saida.stderr);
        Err(format!("`remoteid preparar` retornou erro:\n{}", err.trim()))
    }
}

/// Exibe um diálogo de mensagem de erro.
pub fn mostrar_erro(janela: &impl IsA<gtk::Window>, titulo: &str, mensagem: &str) {
    let dialogo = adw::MessageDialog::builder()
        .heading(titulo)
        .body(mensagem)
        .build();

    dialogo.set_transient_for(Some(janela.as_ref()));
    dialogo.add_response("ok", "OK");
    dialogo.set_default_response(Some("ok"));
    dialogo.present();
}
