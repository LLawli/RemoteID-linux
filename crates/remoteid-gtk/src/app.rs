//! Ciclo de vida da aplicação GTK4, orquestrador do socket UNIX e navegação entre telas.
//!
//! Integra o servidor do socket via `glib::unix_fd_add_local` para atender o módulo
//! PKCS#11 na mesma thread da interface, mantendo a proteção contra reentrância através
//! de `try_borrow_mut` no `Servico`.
//!
//! O atendimento é dividido em DUAS `GSource` (listener e conexão) de propósito:
//! o GLib não redespacha uma `GSource` enquanto o callback dela está na pilha, e
//! o diálogo de PIN/OTP roda um `MainLoop` ANINHADO dentro desse callback. Com
//! uma source só, o próprio `accept` ficava congelado enquanto o diálogo estava
//! aberto: a segunda requisição não era aceita, o cliente ficava pendurado até o
//! timeout dele, e o `try_borrow_mut` abaixo nunca era alcançado. Ver
//! `iniciar_socket` e `registrar_conexao`.

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
            eprintln!(
                "Aviso: Falha ao iniciar socket UNIX em {}: {e}",
                caminho_socket.display()
            );
        }
    }

    // Inicializa a navegação da interface
    navegar_para_estado_atual(&janela, &servico, teste);
    janela.present();
}

/// Sobe o socket UNIX não-bloqueante e integra ao loop de eventos do GLib.
pub fn iniciar_socket(servico: ServicoCompartilhado, caminho: PathBuf) -> Result<PathBuf, String> {
    limpar_socket(&caminho);
    let listener = socket::bind_manual(&caminho).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let fd = listener.as_raw_fd();
    let listener = Rc::new(listener);

    // Este callback tem de ser CURTO: enquanto ele está na pilha, o GLib não
    // despacha esta source de novo. Ele só aceita e delega — nada de ler ou
    // tratar aqui dentro, senão o diálogo de PIN/OTP (que abre um MainLoop
    // aninhado lá no fundo) tranca o accept junto.
    glib::unix_fd_add_local(fd, glib::IOCondition::IN, move |_, _| {
        loop {
            match listener.accept() {
                Ok((fluxo, _)) => registrar_conexao(&servico, fluxo),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        glib::ControlFlow::Continue
    });

    Ok(caminho)
}

/// Dá a cada conexão aceita a SUA própria `GSource`.
///
/// Duas coisas saem daqui, e nenhuma é estilo:
///
/// 1. Como é outra source, ela despacha normalmente enquanto a source do
///    listener (e a de uma conexão anterior) estão presas no `MainLoop`
///    aninhado do diálogo. É o que faz o `try_borrow_mut` de
///    `atender_conexao` ser alcançável e o cliente ouvir "ocupado" na hora,
///    em vez de esperar o timeout de uma resposta que nunca vinha.
/// 2. A leitura só acontece quando já há byte no fd. O `read_line` era feito
///    logo após o `accept`, então um cliente que conectasse e ficasse calado
///    congelava a interface pelos 5s do `set_read_timeout`.
fn registrar_conexao(servico: &ServicoCompartilhado, fluxo: UnixStream) {
    // Rede de segurança para o caso de uma linha chegar pela metade: o
    // `IOCondition::IN` garante que há dado, não que há a linha inteira.
    let _ = fluxo.set_read_timeout(Some(Duration::from_secs(5)));

    let fd = fluxo.as_raw_fd();
    let servico = servico.clone();
    let fluxo = Rc::new(fluxo);

    // HUP/ERR entram para o cliente que desiste antes de falar não deixar a
    // source viva para sempre. `Break` remove a source, e o drop do `Rc` que
    // ela carrega fecha o fd.
    let condicoes = glib::IOCondition::IN | glib::IOCondition::HUP | glib::IOCondition::ERR;
    glib::unix_fd_add_local(fd, condicoes, move |_, cond| {
        if cond.contains(glib::IOCondition::IN) {
            atender_conexao(&servico, &fluxo);
        }
        // Uma requisição por conexão: é o que o protocolo do socket define
        // (uma linha JSON, uma resposta) e o que o módulo PKCS#11 faz.
        glib::ControlFlow::Break
    });
}

/// Remove o arquivo do socket do sistema de arquivos.
pub fn limpar_socket(caminho: &Path) {
    let _ = std::fs::remove_file(caminho);
}

/// Atende uma conexão recebida no socket UNIX de maneira síncrona e segura contra reentrância.
///
/// Roda na source da própria conexão (ver `registrar_conexao`), então pode ser
/// despachada com o `Servico` já emprestado por uma autorização em andamento —
/// que é exatamente o caso que o `try_borrow_mut` abaixo cobre.
fn atender_conexao(servico: &ServicoCompartilhado, fluxo: &UnixStream) {
    let leitor_fluxo = match fluxo.try_clone() {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut escritor = match fluxo.try_clone() {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut leitor = BufReader::new(leitor_fluxo);
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

/// Chama o `Servico` a partir da janela sem NUNCA panicar por reentrância.
/// `None` quer dizer "ocupado: há uma autorização em andamento".
///
/// A janela precisa disto tanto quanto o socket. Durante o diálogo de PIN/OTP o
/// `Servico` está emprestado, e um `borrow_mut()` num handler de botão
/// derrubaria o app inteiro NO MEIO de uma assinatura. Não é hipotético: o
/// diálogo é modal em relação à janela ATIVA, e quando quem pediu a assinatura
/// foi o Papers (o caso normal) o app está em segundo plano — `active_window()`
/// devolve `None`, o diálogo nasce sem pai, e a janela principal segue clicável.
fn tratar_se_livre(servico: &ServicoCompartilhado, req: Requisicao) -> Option<Resposta> {
    match servico.try_borrow_mut() {
        Ok(mut s) => Some(s.tratar(req)),
        Err(_) => None,
    }
}

/// Diz ao usuário por que o clique dele não fez nada.
fn avisar_ocupado(janela: &impl IsA<gtk::Window>) {
    mostrar_erro(
        janela,
        "Autorização em andamento",
        "Conclua (ou cancele) o diálogo de PIN e OTP antes de usar a janela.",
    );
}

/// Consulta o estado atual e renderiza a tela apropriada (Login ou Painel).
pub fn navegar_para_estado_atual(
    janela: &adw::ApplicationWindow,
    servico: &ServicoCompartilhado,
    teste: bool,
) {
    // Ocupado: mantém a tela como está. Renavegar não é urgente, e derrubar o
    // app por causa de um refresh de tela seria péssimo troco.
    let Some(status_resp) = tratar_se_livre(servico, Requisicao::Status) else {
        return;
    };
    let estado = match status_resp {
        Resposta::Sucesso(ref s) => {
            EstadoApp::de_status(s).unwrap_or_else(EstadoApp::mock_nao_preparado)
        }
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

            glib::timeout_add_local(Duration::from_millis(100), move || match rx.try_recv() {
                Ok(resultado) => {
                    match resultado {
                        Ok(()) => {
                            match s_async.try_borrow_mut() {
                                Ok(mut s) => {
                                    if let Err(e) = s.reabrir() {
                                        drop(s);
                                        mostrar_erro(
                                            &j_async,
                                            "Instalação concluída com ressalva",
                                            &format!(
                                                "O estado foi gravado, mas a recarga falhou: {e}"
                                            ),
                                        );
                                    }
                                }
                                Err(_) => avisar_ocupado(&j_async),
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
            let Some(r) = tratar_se_livre(&s_painel, Requisicao::ReautorizarProxima) else {
                avisar_ocupado(&j_painel);
                return;
            };
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
    let Some(status_resp) = tratar_se_livre(servico, Requisicao::Status) else {
        avisar_ocupado(janela);
        return;
    };
    let estado = match status_resp {
        Resposta::Sucesso(ref s) => {
            EstadoApp::de_status(s).unwrap_or_else(EstadoApp::mock_nao_preparado)
        }
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
            let Some(r) = tratar_se_livre(&s_sel, Requisicao::EscolherCertificado { key_name })
            else {
                avisar_ocupado(&j_sel);
                return;
            };
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
    let Some(status_resp) = tratar_se_livre(servico, Requisicao::Status) else {
        avisar_ocupado(janela);
        return;
    };
    let estado = match status_resp {
        Resposta::Sucesso(ref s) => {
            EstadoApp::de_status(s).unwrap_or_else(EstadoApp::mock_nao_preparado)
        }
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
            let Some(r) = tratar_se_livre(&s_cfg, Requisicao::Reinstalar) else {
                avisar_ocupado(&j_cfg);
                return;
            };
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
        Err(format!(
            "`remoteid preparar` retornou erro:\n{}",
            err.trim()
        ))
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
