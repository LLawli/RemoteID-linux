//! O binário `remoteid-app`: o app unificado do RemoteID-linux.
//!
//! Unificação de 03/09/2026 ([[remoteid-app-unificado]]): um binário só, sem
//! daemon separado e sem socket activation. A janela roda o servidor do socket
//! **no próprio processo** (ver [`servidor`]) — então **assinar só funciona
//! enquanto a janela está aberta**. Um consumidor (Firefox/Papers) que tente
//! assinar com o app fechado recebe conexão recusada.
//!
//! Dois modos:
//!
//! - **normal** — abre a janela, sobe o servidor do socket (para o módulo
//!   PKCS#11), e a janela fala com o [`Servico`] **direto** (sem round-trip de
//!   socket consigo mesma). Se não estiver preparado, mostra o wizard que roda
//!   o CLI `remoteid preparar`.
//! - **`--preview`** — NÃO cria motor nem socket. Abre a galeria de telas com
//!   dados fictícios ([`modelo`] `mock_*`), para validação visual. Alvo do
//!   `make preview`.

mod gtk_prompter;
mod servidor;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use gtk::prelude::*;

use remoteid_core::Opcoes;
use remoteid_daemon::protocolo::{CodigoErro, Requisicao, Resposta, SucessoResposta};
use remoteid_daemon::servico::Servico;
use remoteid_gtk::modelo::{self, ConfigApp, EstadoApp};
use remoteid_gtk::telas;

use crate::gtk_prompter::GtkPrompter;

const ID_APP: &str = "dev.lukakuuhaku.RemoteID";
const ID_PREVIEW: &str = "dev.lukakuuhaku.RemoteID.Preview";
const ID_TESTE: &str = "dev.lukakuuhaku.RemoteID.Teste";

/// O `Servico` compartilhado entre a janela (thread principal) e o servidor do
/// socket (também na thread principal, via watch de FD do glib). `Rc<RefCell>`
/// basta porque tudo é single-thread; o diálogo modal de assinatura bloqueia a
/// janela e o servidor usa `try_borrow_mut`, então não há reentrância.
type ServicoCompartilhado = Rc<RefCell<Servico>>;

fn main() -> gtk::glib::ExitCode {
    let preview = std::env::args().any(|a| a == "--preview");
    let teste = !preview && std::env::var("TEST_URL").is_ok_and(|v| !v.is_empty());

    let id = if preview {
        ID_PREVIEW
    } else if teste {
        // App-id próprio: o modo de teste roda como instância separada, então
        // convive com uma instância normal aberta sem uma "sequestrar" a outra.
        ID_TESTE
    } else {
        ID_APP
    };
    let app = gtk::Application::builder().application_id(id).build();

    if preview {
        app.connect_activate(construir_preview);
    } else {
        app.connect_activate(construir_app);
    }

    // Não deixamos o GTK parsear nossos argumentos (`--preview` é nosso).
    app.run_with_args(&Vec::<String>::new())
}

/// Decide `Opcoes`, caminho do socket e se é modo de teste, a partir de
/// `TEST_URL`. Em teste, estado/diag/URL vão para /tmp e o mock; nada toca a
/// conta real. Ver [[remoteid-app-unificado]] e o `remoteid-mock`.
fn ambiente() -> (Opcoes, PathBuf, bool) {
    // `Opcoes::default()` e `socket::caminho_padrao()` já respeitam `TEST_URL`
    // (estado, diag e socket em /tmp). Aqui só reportamos a flag para o título.
    let opcoes = Opcoes::default();
    let socket = remoteid_daemon::socket::caminho_padrao();
    let teste = remoteid_core::state::em_teste();
    (opcoes, socket, teste)
}

// ===========================================================================
// Modo normal: a janela + o servidor do socket, no mesmo processo
// ===========================================================================

fn construir_app(app: &gtk::Application) {
    let (opcoes, caminho_socket, teste) = ambiente();

    let titulo = if teste { "RemoteID — MODO DE TESTE" } else { "RemoteID" };
    let janela = gtk::ApplicationWindow::builder()
        .application(app)
        .title(titulo)
        .default_width(560)
        .default_height(640)
        .build();

    // Abre o motor com o prompter GTK. Falha aqui é fatal para o app.
    let servico = match Servico::novo(opcoes, Box::new(GtkPrompter::novo())) {
        Ok(s) => Rc::new(RefCell::new(s)),
        Err(e) => {
            let slot = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
            janela.set_child(Some(&slot));
            slot.append(&banner_estatico(
                "Não deu para abrir o motor",
                &format!("{e}\n\nO app não pode continuar."),
            ));
            janela.present();
            return;
        }
    };

    // Sobe o servidor do socket (para o módulo PKCS#11). Se falhar, a janela
    // ainda serve para preparar/inspecionar; só a assinatura externa não vai.
    match servidor::iniciar(servico.clone(), caminho_socket) {
        Ok(caminho) => {
            // Limpa o arquivo do socket quando o app sai.
            app.connect_shutdown(move |_| servidor::limpar(&caminho));
        }
        Err(e) => eprintln!("remoteid-app: servidor do socket não subiu: {e}"),
    }

    let slot = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
    janela.set_child(Some(&slot));

    renderizar_principal(&slot, &servico);
    janela.present();
}

/// Consulta o estado (via `Servico` direto) e mostra a tela correspondente.
/// Recursiva: as ações dos botões chamam esta função de novo para recarregar.
fn renderizar_principal(slot: &gtk::Box, servico: &ServicoCompartilhado) {
    let resposta = servico.borrow_mut().tratar(Requisicao::Status);
    match resposta {
        Resposta::Sucesso(SucessoResposta::Status {
            preparado,
            titular,
            codigo_desktop,
            certificados,
            sessoes,
            ..
        }) => {
            if !preparado {
                trocar(slot, &tela_login(slot, servico));
            } else {
                let estado = mapear_estado(titular, codigo_desktop, certificados, sessoes);
                trocar(slot, &telas::inicial(&estado, acoes_inicial(slot, servico)));
            }
        }
        Resposta::Falha { codigo: CodigoErro::NaoPreparado, .. } => {
            trocar(slot, &tela_login(slot, servico));
        }
        Resposta::Falha { erro, .. } => trocar(slot, &banner(slot, servico, "Erro", &erro)),
        Resposta::Sucesso(_) => {
            trocar(slot, &banner(slot, servico, "Resposta inesperada", "Estado fora do previsto."))
        }
    }
}

fn mapear_estado(
    titular: Option<String>,
    codigo_desktop: Option<String>,
    certificados: Vec<remoteid_daemon::protocolo::CertificadoResumo>,
    sessoes: Vec<remoteid_daemon::protocolo::SessaoResumo>,
) -> EstadoApp {
    let titular_geral = titular.clone().unwrap_or_default();
    EstadoApp {
        preparado: true,
        titular,
        codigo_desktop,
        certificados: certificados
            .into_iter()
            .map(|c| modelo::Certificado {
                titular: titular_geral.clone(),
                emissor: c.issue,
                serial: c.serial_number,
                key_name: c.key_name,
            })
            .collect(),
        sessoes: sessoes
            .into_iter()
            .map(|s| modelo::Sessao {
                cert_key: s.cert_key,
                emitido_em: s.emitido_em,
                visto_em: s.visto_em,
            })
            .collect(),
    }
}

fn acoes_inicial(slot: &gtk::Box, servico: &ServicoCompartilhado) -> telas::AcoesInicial {
    let (s1, sv1) = (slot.clone(), servico.clone());
    let (s2, sv2) = (slot.clone(), servico.clone());
    telas::AcoesInicial {
        reautorizar: Rc::new(move || {
            let r = sv1.borrow_mut().tratar(Requisicao::ReautorizarProxima);
            if let Resposta::Falha { erro, .. } = r {
                alerta(&s1, "Não deu para reautorizar", &erro);
            }
            renderizar_principal(&s1, &sv1);
        }),
        abrir_config: Rc::new(move || trocar(&s2, &tela_config(&s2, &sv2))),
    }
}

fn tela_login(slot: &gtk::Box, servico: &ServicoCompartilhado) -> gtk::Widget {
    let (s, sv) = (slot.clone(), servico.clone());
    telas::login(telas::AcoesLogin {
        preparar: Rc::new(move |email, senha| {
            // Bloqueia o loop enquanto o CLI faz login+registro+carteira (rede).
            // Idealmente iria para uma thread com marshaling por glib; hoje a
            // janela "congela" alguns segundos. Nunca passamos a senha por
            // argumento (visível em `ps`): só por variável de ambiente.
            match preparar_via_cli(&email, &senha) {
                Ok(()) => {
                    // O CLI gravou o state.json num processo separado; reabrimos
                    // o motor para o Servico enxergar o novo estado.
                    if let Err(e) = sv.borrow_mut().reabrir() {
                        alerta(&s, "Preparado, mas não recarregou", &e.to_string());
                    }
                    renderizar_principal(&s, &sv);
                }
                Err(msg) => alerta(&s, "Falha ao preparar", &msg),
            }
        }),
    })
}

fn tela_config(slot: &gtk::Box, servico: &ServicoCompartilhado) -> gtk::Widget {
    let cfg = carregar_config();
    let (s_reinst, sv_reinst) = (slot.clone(), servico.clone());
    let (s_voltar, sv_voltar) = (slot.clone(), servico.clone());
    let s_salvar = slot.clone();
    let log_path = cfg.caminho_log.clone();
    telas::configuracoes(
        &cfg,
        telas::AcoesConfig {
            reinstalar: Rc::new(move || {
                let r = sv_reinst.borrow_mut().tratar(Requisicao::Reinstalar);
                if let Resposta::Falha { erro, .. } = r {
                    alerta(&s_reinst, "Não deu para reinstalar", &erro);
                }
                renderizar_principal(&s_reinst, &sv_reinst);
            }),
            salvar: Rc::new(move |novo| match salvar_config(&novo) {
                Ok(caminho) => alerta(
                    &s_salvar,
                    "Configuração salva",
                    &format!(
                        "Salvo em {caminho}. O motor passa a ler estes valores numa \
                         versão futura (hoje eles são registrados, não aplicados)."
                    ),
                ),
                Err(e) => alerta(&s_salvar, "Não deu para salvar", &e),
            }),
            abrir_pasta_log: Rc::new(move || abrir_pasta(&log_path)),
            voltar: Rc::new(move || renderizar_principal(&s_voltar, &sv_voltar)),
        },
    )
}

// --- helpers do modo normal ---

/// Troca o filho único do `slot`.
fn trocar(slot: &gtk::Box, filho: &impl IsA<gtk::Widget>) {
    while let Some(c) = slot.first_child() {
        slot.remove(&c);
    }
    slot.append(filho);
}

/// Tela de aviso com botão "Tentar de novo" (que re-renderiza).
fn banner(slot: &gtk::Box, servico: &ServicoCompartilhado, titulo: &str, msg: &str) -> gtk::Widget {
    let raiz = caixa_centrada(titulo, msg);
    let btn = gtk::Button::with_label("Tentar de novo");
    btn.add_css_class("suggested-action");
    btn.set_halign(gtk::Align::Center);
    let (s, sv) = (slot.clone(), servico.clone());
    btn.connect_clicked(move |_| renderizar_principal(&s, &sv));
    raiz.append(&btn);
    raiz.upcast()
}

/// Banner sem botão (para erro fatal de inicialização).
fn banner_estatico(titulo: &str, msg: &str) -> gtk::Widget {
    caixa_centrada(titulo, msg).upcast()
}

fn caixa_centrada(titulo: &str, msg: &str) -> gtk::Box {
    let raiz = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(14)
        .margin_top(28)
        .margin_bottom(28)
        .margin_start(28)
        .margin_end(28)
        .valign(gtk::Align::Center)
        .build();
    raiz.append(&gtk::Label::builder().label(titulo).css_classes(["title-2"]).build());
    raiz.append(
        &gtk::Label::builder().label(msg).wrap(true).justify(gtk::Justification::Center).build(),
    );
    raiz
}

/// Um alerta modal simples (transiente à janela do `anchor`), com um OK.
fn alerta(anchor: &gtk::Box, titulo: &str, msg: &str) {
    let dialogo = gtk::Window::builder().title(titulo).modal(true).resizable(false).default_width(380).build();
    if let Some(w) = anchor.root().and_downcast::<gtk::Window>() {
        dialogo.set_transient_for(Some(&w));
    }
    let caixa = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(14)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    caixa.append(&gtk::Label::builder().label(msg).wrap(true).xalign(0.0).build());
    let ok = gtk::Button::with_label("OK");
    ok.set_halign(gtk::Align::End);
    caixa.append(&ok);
    dialogo.set_child(Some(&caixa));
    let d = dialogo.clone();
    ok.connect_clicked(move |_| d.close());
    dialogo.present();
}

/// Roda `remoteid preparar` com as credenciais via ambiente.
fn preparar_via_cli(email: &str, senha: &str) -> Result<(), String> {
    let saida = std::process::Command::new("remoteid")
        .arg("preparar")
        .env("REMOTEID_EMAIL", email)
        .env("REMOTEID_SENHA", senha)
        .output()
        .map_err(|e| format!("não consegui executar `remoteid`: {e}. Ele está no PATH?"))?;
    if saida.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&saida.stderr);
        Err(format!("`remoteid preparar` falhou:\n{}", err.trim()))
    }
}

fn abrir_pasta(caminho: &str) {
    let expandido = expandir_til(caminho);
    let _ = std::process::Command::new("xdg-open").arg(&expandido).spawn();
}

fn expandir_til(caminho: &str) -> String {
    if let Some(resto) = caminho.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{resto}");
        }
    }
    caminho.to_string()
}

/// Config atual. Hoje só os padrões (o motor ainda não lê `config.toml`); o
/// caminho do log vem do XDG. Quando o motor passar a ler, isto lê de volta.
fn carregar_config() -> ConfigApp {
    let base = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            std::env::var("HOME").map(|h| format!("{h}/.local/state")).unwrap_or_default()
        });
    ConfigApp {
        cache_pin_min: 5,
        ttl_sessao_min: 15,
        nome_aplicacao: "RemoteID-linux".to_string(),
        caminho_log: format!("{base}/remoteid/diag"),
    }
}

/// Persiste a config em `~/.config/remoteid/config.toml` (groundwork: o motor
/// ainda não a consome). TOML escrito à mão para não puxar dependência.
fn salvar_config(cfg: &ConfigApp) -> Result<String, String> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            std::env::var("HOME").map(|h| format!("{h}/.config")).unwrap_or_default()
        });
    let dir = format!("{base}/remoteid");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let caminho = format!("{dir}/config.toml");
    let conteudo = format!(
        "# Configuração do RemoteID-linux (escrita pela janela).\n\
         cache_pin_min = {}\n\
         ttl_sessao_min = {}\n\
         nome_aplicacao = \"{}\"\n",
        cfg.cache_pin_min,
        cfg.ttl_sessao_min,
        cfg.nome_aplicacao.replace('"', "'"),
    );
    std::fs::write(&caminho, conteudo).map_err(|e| e.to_string())?;
    Ok(caminho)
}

// ===========================================================================
// Modo --preview: a galeria de telas com dados mock (sem motor, sem socket)
// ===========================================================================

fn construir_preview(app: &gtk::Application) {
    let janela = gtk::ApplicationWindow::builder()
        .application(app)
        .title("RemoteID — preview das telas (dados fictícios)")
        .default_width(820)
        .default_height(660)
        .build();

    let stack = gtk::Stack::builder().transition_type(gtk::StackTransitionType::Crossfade).build();
    let sidebar = gtk::StackSidebar::builder().stack(&stack).build();

    // Login / instalação
    stack.add_titled(
        &telas::login(telas::AcoesLogin {
            preparar: Rc::new(|email, _senha| println!("[preview] preparar: email={email} (senha omitida)")),
        }),
        Some("login"),
        "Login / instalação",
    );

    // Seleção de token (dois certificados)
    let multi = EstadoApp::mock_multi_token();
    stack.add_titled(
        &telas::selecao_token(
            &multi.certificados,
            telas::AcoesSelecao { escolher: Rc::new(|i| println!("[preview] token escolhido: {i}")) },
        ),
        Some("selecao"),
        "Seleção de token",
    );

    // Tela inicial (preparado) — o botão de config leva à página de config.
    {
        let stack_ref = stack.clone();
        let inicial = telas::inicial(
            &EstadoApp::mock_preparado(),
            telas::AcoesInicial {
                reautorizar: Rc::new(|| println!("[preview] reautorizar próxima assinatura")),
                abrir_config: Rc::new(move || stack_ref.set_visible_child_name("config")),
            },
        );
        stack.add_titled(&inicial, Some("inicial"), "Tela inicial");
    }

    // Tela inicial (não preparado)
    stack.add_titled(
        &telas::inicial(
            &EstadoApp::mock_nao_preparado(),
            telas::AcoesInicial { reautorizar: Rc::new(|| {}), abrir_config: Rc::new(|| {}) },
        ),
        Some("nao_prep"),
        "Inicial (não preparado)",
    );

    // Configurações — o botão Reinstalar mostra o diálogo vermelho de verdade.
    {
        let stack_ref = stack.clone();
        let config = telas::configuracoes(
            &ConfigApp::mock(),
            telas::AcoesConfig {
                reinstalar: Rc::new(|| println!("[preview] REINSTALAR confirmado")),
                salvar: Rc::new(|c| println!("[preview] salvar config: cache={}min ttl={}min nome={}", c.cache_pin_min, c.ttl_sessao_min, c.nome_aplicacao)),
                abrir_pasta_log: Rc::new(|| println!("[preview] abrir pasta do log")),
                voltar: Rc::new(move || stack_ref.set_visible_child_name("inicial")),
            },
        );
        stack.add_titled(&config, Some("config"), "Configurações");
    }

    // PIN / OTP — a MESMA tela que o app mostra ao assinar (montada, não modal,
    // para caber embutida na galeria).
    {
        let d = telas::pin_otp::montar(Some("MARIA SILVA:12345678900"), Some("Papers"), Some("1234"));
        let moldura = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .halign(gtk::Align::Center)
            .valign(gtk::Align::Center)
            .vexpand(true)
            .build();
        d.botao_ok.connect_clicked(|_| println!("[preview] assinar (PIN/OTP confirmados)"));
        d.botao_cancelar.connect_clicked(|_| println!("[preview] assinatura cancelada"));
        moldura.append(&d.raiz);
        stack.add_titled(&moldura, Some("pinotp"), "PIN / OTP (assinar)");
    }

    let caixa = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).build();
    sidebar.set_size_request(210, -1);
    caixa.append(&sidebar);
    caixa.append(&gtk::Separator::new(gtk::Orientation::Vertical));
    stack.set_hexpand(true);
    caixa.append(&stack);
    janela.set_child(Some(&caixa));
    janela.present();
}
