//! A janela: entrar na conta, a carteira em cartões, os detalhes e sair.
//!
//! O estado vem antes dos controles. O certificado que assina é um cartão com
//! um selo (cadeado aberto até a hora em que a sessão vence, ou fechado quando
//! a próxima assinatura pede PIN e OTP); trocar de certificado é passar o
//! cartão; os detalhes sobem de baixo.
//!
//! A janela não guarda estado próprio: relê o `estado.json` a cada
//! [`RELEITURA`], porque o módulo PKCS#11 abre e fecha sessões sem avisar, e
//! desenha o que [`carteira::montar`] devolve. Rede fica fora da thread da
//! interface; o resto (escolher, reautorizar, sair) só toca o disco.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::{gio, glib};
use remoteid::caminhos::{self, Caminhos};
use remoteid::carteira::{self, Cartao, Carteira, Sessao};
use remoteid::cofre;
use remoteid::diagnostico::Diagnostico;
use remoteid::estado::Estado;
use remoteid::motor::{Erro, Motor};
use remoteid::pin;
use remoteid::protocolo::requisicao::Maquina;
use remoteid::transporte::{Http, TEMPO_LIMITE};
use remoteid::{NOME, id_do_aplicativo};

use zeroize::Zeroizing;

use super::cartao::{self, Grande, texto};
use super::estilo;

/// De quanto em quanto tempo a janela relê o estado.
const RELEITURA: Duration = Duration::from_secs(2);

/// Quantos segundos o "Desfazer" de sair fica na tela. A conta só sai do
/// disco quando ele some, ou quando a janela fecha.
const DESFAZER_S: u32 = 8;

struct Janela {
    caminhos: Caminhos,
    /// Um registro para a janela inteira, dividido pelas operações.
    diagnostico: Diagnostico,
    janela: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    pilha: gtk::Stack,
    titulo: gtk::Box,
    avatar: adw::Avatar,
    nome: gtk::Label,
    menu: gtk::MenuButton,
    folha: adw::BottomSheet,
    carrossel: adw::Carousel,
    navegacao: gtk::Box,
    anterior: gtk::Button,
    proximo: gtk::Button,
    usar: gtk::Revealer,
    email: adw::EntryRow,
    senha: adw::PasswordEntryRow,
    botao_entrar: gtk::Button,
    erro: gtk::Box,
    erro_texto: gtk::Label,
    pin: adw::PasswordEntryRow,
    pin_repetido: adw::PasswordEntryRow,
    botao_pin: gtk::Button,
    erro_pin: gtk::Box,
    erro_pin_texto: gtk::Label,
    /// A senha do login, enquanto a pessoa cria o PIN que vai protegê-la.
    senha_pendente: RefCell<Option<Zeroizing<String>>>,
    acao_reautorizar: gio::SimpleAction,
    acao_usar: gio::SimpleAction,
    /// A carteira desenhada agora.
    carteira: RefCell<Option<Carteira>>,
    cartoes: RefCell<Vec<Grande>>,
    paginas: RefCell<Vec<gtk::Widget>>,
    /// O cartão à vista no carrossel.
    visto: Cell<usize>,
    entrando: Cell<bool>,
    /// Entrou sem chaveiro e está criando o PIN.
    criando_pin: Cell<bool>,
    /// Saiu, e o "Desfazer" ainda está na tela.
    saindo: Cell<bool>,
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A janela do aplicativo, criada na primeira ativação.
pub fn abrir(app: &adw::Application) {
    if let Some(janela) = app.active_window() {
        janela.present();
        return;
    }
    estilo::instalar();
    let j = construir(app);
    ligar(app, &j);
    recarregar(&j);
    if j.carteira.borrow().is_none() {
        mostrar_tela(&j, false);
    } else {
        // A carteira pode ter mudado desde a última vez: certificado
        // renovado, outro acrescentado. Sem rede, fica a que havia.
        em_segundo_plano(&j, Motor::atualizar_carteira, |j, _| recarregar(j));
    }
    let fraca = Rc::downgrade(&j);
    glib::timeout_add_local(RELEITURA, move || match fraca.upgrade() {
        Some(j) => {
            recarregar(&j);
            glib::ControlFlow::Continue
        }
        None => glib::ControlFlow::Break,
    });
    j.janela.present();
    focar(&j);
}

fn motor(caminhos: &Caminhos, diagnostico: Diagnostico) -> Result<Motor, Erro> {
    let m = Motor::abrir(
        caminhos.clone(),
        caminhos::servidor(),
        Box::new(Http::novo(TEMPO_LIMITE)),
    )?
    .com_cofre(cofre::do_ambiente());
    Ok(m.com_diagnostico(diagnostico))
}

/// O que vai à rede roda numa thread, com um motor próprio, e `depois` volta
/// para a thread da interface. O diagnóstico registra a conversa.
fn em_segundo_plano<T: Send + 'static>(
    j: &Rc<Janela>,
    op: impl FnOnce(&mut Motor) -> Result<T, Erro> + Send + 'static,
    depois: impl FnOnce(&Rc<Janela>, Result<T, Erro>) + 'static,
) {
    let caminhos = j.caminhos.clone();
    let diagnostico = j.diagnostico.clone();
    let tarefa = gio::spawn_blocking(move || op(&mut motor(&caminhos, diagnostico)?));
    let j = j.clone();
    glib::spawn_future_local(async move {
        let resultado = tarefa
            .await
            .unwrap_or(Err(Erro::NaoPreparado("a operação parou no meio")));
        depois(&j, resultado);
    });
}

/// O que só toca o disco roda aqui mesmo.
fn no_disco(j: &Rc<Janela>, op: impl FnOnce(&mut Motor) -> Result<(), Erro>) {
    if let Err(e) = motor(&j.caminhos, j.diagnostico.clone()).and_then(|mut m| op(&mut m)) {
        j.toasts.add_toast(adw::Toast::new(&e.to_string()));
    }
    recarregar(j);
}

fn construir_entrar() -> (
    gtk::Widget,
    adw::EntryRow,
    adw::PasswordEntryRow,
    gtk::Button,
    gtk::Box,
    gtk::Label,
) {
    let marca = gtk::Box::builder()
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .css_classes(["marca"])
        .build();
    marca.append(
        &gtk::Image::builder()
            .icon_name("application-certificate-symbolic")
            .pixel_size(40)
            .hexpand(true)
            .build(),
    );

    let email = adw::EntryRow::builder()
        .title("E-mail")
        .input_purpose(gtk::InputPurpose::Email)
        .build();
    email.add_prefix(&gtk::Image::from_icon_name("mail-unread-symbolic"));
    let senha = adw::PasswordEntryRow::builder().title("Senha").build();
    senha.add_prefix(&gtk::Image::from_icon_name("dialog-password-symbolic"));
    let campos = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    campos.append(&email);
    campos.append(&senha);

    let erro_texto = gtk::Label::builder().wrap(true).build();
    let erro = gtk::Box::builder()
        .spacing(6)
        .halign(gtk::Align::Center)
        .css_classes(["error"])
        .visible(false)
        .build();
    erro.append(&gtk::Image::from_icon_name("dialog-error-symbolic"));
    erro.append(&erro_texto);

    let botao = gtk::Button::builder()
        .label("Entrar")
        .halign(gtk::Align::Center)
        .width_request(180)
        .css_classes(["suggested-action", "pill"])
        .build();

    let nome = texto(NOME, &["title-1"]);
    nome.set_xalign(0.5);
    nome.set_margin_bottom(8);
    let coluna = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(20)
        .valign(gtk::Align::Center)
        .margin_start(16)
        .margin_end(16)
        .margin_bottom(40)
        .build();
    coluna.append(&marca);
    coluna.append(&nome);
    coluna.append(&campos);
    coluna.append(&erro);
    coluna.append(&botao);

    let clamp = adw::Clamp::builder()
        .maximum_size(360)
        .tightening_threshold(320)
        .child(&coluna)
        .build();
    (clamp.upcast(), email, senha, botao, erro, erro_texto)
}

/// A tela de criar o PIN local, quando o sistema não tem chaveiro.
fn construir_pin() -> (
    gtk::Widget,
    adw::PasswordEntryRow,
    adw::PasswordEntryRow,
    gtk::Button,
    gtk::Box,
    gtk::Label,
) {
    let marca = gtk::Box::builder()
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .css_classes(["marca"])
        .build();
    marca.append(
        &gtk::Image::builder()
            .icon_name("system-lock-screen-symbolic")
            .pixel_size(40)
            .hexpand(true)
            .build(),
    );
    let titulo = texto("Crie um PIN", &["title-2"]);
    titulo.set_xalign(0.5);

    let novo = |rotulo: &str| {
        let campo = adw::PasswordEntryRow::builder()
            .title(rotulo)
            .input_purpose(gtk::InputPurpose::Pin)
            .build();
        campo.add_prefix(&gtk::Image::from_icon_name("dialog-password-symbolic"));
        campo
    };
    let pin = novo("PIN");
    let repetido = novo("Repita o PIN");
    let campos = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    campos.append(&pin);
    campos.append(&repetido);

    let erro_texto = gtk::Label::builder().wrap(true).build();
    let erro = gtk::Box::builder()
        .spacing(6)
        .halign(gtk::Align::Center)
        .css_classes(["error"])
        .visible(false)
        .build();
    erro.append(&gtk::Image::from_icon_name("dialog-error-symbolic"));
    erro.append(&erro_texto);

    let botao = gtk::Button::builder()
        .label("Guardar")
        .halign(gtk::Align::Center)
        .width_request(180)
        .sensitive(false)
        .css_classes(["suggested-action", "pill"])
        .build();

    let coluna = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(20)
        .valign(gtk::Align::Center)
        .margin_start(16)
        .margin_end(16)
        .margin_bottom(40)
        .build();
    coluna.append(&marca);
    coluna.append(&titulo);
    coluna.append(&campos);
    coluna.append(&erro);
    coluna.append(&botao);
    let clamp = adw::Clamp::builder()
        .maximum_size(360)
        .tightening_threshold(320)
        .child(&coluna)
        .build();
    (clamp.upcast(), pin, repetido, botao, erro, erro_texto)
}

fn botao_redondo(icone: &str, dica: &str) -> gtk::Button {
    gtk::Button::builder()
        .icon_name(icone)
        .css_classes(["flat", "circular"])
        .tooltip_text(dica)
        .valign(gtk::Align::Center)
        .build()
}

fn construir(app: &adw::Application) -> Rc<Janela> {
    let (pagina_entrar, email, senha, botao_entrar, erro, erro_texto) = construir_entrar();
    let (pagina_pin, pin, pin_repetido, botao_pin, erro_pin, erro_pin_texto) = construir_pin();

    let carrossel = adw::Carousel::builder()
        .spacing(28)
        .allow_mouse_drag(true)
        .height_request(250)
        .build();
    let anterior = botao_redondo("go-previous-symbolic", "Anterior");
    let proximo = botao_redondo("go-next-symbolic", "Próximo");
    let navegacao = gtk::Box::builder()
        .spacing(10)
        .halign(gtk::Align::Center)
        .build();
    navegacao.append(&anterior);
    navegacao.append(
        &adw::CarouselIndicatorDots::builder()
            .carousel(&carrossel)
            .build(),
    );
    navegacao.append(&proximo);

    let botao_usar = gtk::Button::builder()
        .halign(gtk::Align::Center)
        .action_name("win.usar")
        .css_classes(["suggested-action", "pill"])
        .child(
            &adw::ButtonContent::builder()
                .icon_name("object-select-symbolic")
                .label("Usar")
                .build(),
        )
        .build();
    let usar = gtk::Revealer::builder()
        .transition_type(gtk::RevealerTransitionType::SlideUp)
        .child(&botao_usar)
        .valign(gtk::Align::Start)
        .hexpand(true)
        .build();
    // O espaço do "Usar" fica reservado, para os cartões não pularem.
    let reserva = gtk::Box::builder()
        .height_request(60)
        .margin_top(12)
        .build();
    reserva.append(&usar);

    let pagina_carteira = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    pagina_carteira.append(&gtk::Box::builder().vexpand(true).build());
    pagina_carteira.append(&carrossel);
    pagina_carteira.append(&navegacao);
    pagina_carteira.append(&reserva);
    pagina_carteira.append(&gtk::Box::builder().vexpand(true).build());

    let pilha = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();
    pilha.add_named(&pagina_entrar, Some("entrar"));
    pilha.add_named(&pagina_carteira, Some("carteira"));
    pilha.add_named(&pagina_pin, Some("pin"));

    let barra = gtk::Box::builder()
        .spacing(8)
        .halign(gtk::Align::Center)
        .css_classes(["barra-detalhes"])
        .build();
    barra.append(&gtk::Image::from_icon_name("pan-up-symbolic"));
    barra.append(&gtk::Label::new(Some("Detalhes")));
    let folha = adw::BottomSheet::builder()
        .content(&pilha)
        .bottom_bar(&barra)
        .show_drag_handle(true)
        .full_width(true)
        .reveal_bottom_bar(false)
        .can_open(false)
        .build();

    let avatar = adw::Avatar::new(24, None, true);
    let nome = texto("", &["heading"]);
    nome.set_ellipsize(gtk::pango::EllipsizeMode::End);
    let titulo = gtk::Box::builder().spacing(8).visible(false).build();
    titulo.append(&avatar);
    titulo.append(&nome);

    let acoes = gio::Menu::new();
    acoes.append(Some("Reautorizar"), Some("win.reautorizar"));
    acoes.append(Some("Sair da conta"), Some("win.sair"));
    let sobre = gio::Menu::new();
    sobre.append(Some("Sobre o RemoteID"), Some("win.sobre"));
    let modelo = gio::Menu::new();
    modelo.append_section(None, &acoes);
    modelo.append_section(None, &sobre);
    let menu = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&modelo)
        .primary(true)
        .tooltip_text("Menu")
        .visible(false)
        .build();
    let cabecalho = adw::HeaderBar::builder().title_widget(&titulo).build();
    cabecalho.pack_end(&menu);

    let barras = adw::ToolbarView::builder()
        .top_bar_style(adw::ToolbarStyle::Flat)
        .content(&folha)
        .build();
    barras.add_top_bar(&cabecalho);
    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&barras));

    let janela = adw::ApplicationWindow::builder()
        .application(app)
        .title(NOME)
        .icon_name(id_do_aplicativo())
        .default_width(460)
        .default_height(740)
        .content(&toasts)
        .build();

    let caminhos = Caminhos::do_ambiente();
    Rc::new(Janela {
        diagnostico: Diagnostico::abrir(&caminhos.diagnostico(), "janela"),
        caminhos,
        janela,
        toasts,
        pilha,
        titulo,
        avatar,
        nome,
        menu,
        folha,
        carrossel,
        navegacao,
        anterior,
        proximo,
        usar,
        email,
        senha,
        botao_entrar,
        erro,
        erro_texto,
        pin,
        pin_repetido,
        botao_pin,
        erro_pin,
        erro_pin_texto,
        senha_pendente: RefCell::new(None),
        acao_reautorizar: gio::SimpleAction::new("reautorizar", None),
        acao_usar: gio::SimpleAction::new("usar", None),
        carteira: RefCell::new(None),
        cartoes: RefCell::new(Vec::new()),
        paginas: RefCell::new(Vec::new()),
        visto: Cell::new(0),
        entrando: Cell::new(false),
        criando_pin: Cell::new(false),
        saindo: Cell::new(false),
    })
}

/// Relê o estado e desenha o que mudou. Enquanto entra ou sai, a tela de
/// entrar fica, seja o que for que o disco diga.
fn recarregar(j: &Rc<Janela>) {
    if j.entrando.get() || j.criando_pin.get() || j.saindo.get() {
        return;
    }
    let Ok(estado) = Estado::carregar(&j.caminhos.estado()) else {
        return;
    };
    match carteira::montar(&estado, agora()) {
        Some(c) => desenhar(j, c),
        None => {
            if j.carteira.take().is_some() || !na_tela(j, "entrar") {
                mostrar_tela(j, false);
            }
        }
    }
}

fn na_tela(j: &Janela, nome: &str) -> bool {
    j.pilha.visible_child_name().as_deref() == Some(nome)
}

/// O que, mudando, pede cartões novos. A sessão e a escolha mudam só o selo e
/// o "Usar".
fn feitio(c: &Carteira, agora: u64) -> Vec<(Cartao, Option<i64>)> {
    c.cartoes
        .iter()
        .map(|cartao| {
            let alerta = cartao.alerta(agora);
            let mut cartao = cartao.clone();
            cartao.ativo = false;
            cartao.sessao = Sessao::Fechada;
            (cartao, alerta)
        })
        .collect()
}

fn desenhar(j: &Rc<Janela>, nova: Carteira) {
    let agora = agora();
    let anterior = j.carteira.borrow_mut().take();
    let mesma_conta = anterior.as_ref().is_some_and(|a| a.email == nova.email);
    let refazer = anterior
        .as_ref()
        .is_none_or(|a| feitio(a, agora) != feitio(&nova, agora));
    if refazer {
        // Fica à vista o mesmo cartão, se ele ainda está na carteira; numa
        // conta que acabou de entrar, o que assina.
        let chave_vista = anterior
            .as_ref()
            .filter(|_| mesma_conta)
            .and_then(|a| a.cartoes.get(j.visto.get()))
            .map(|c| c.chave.clone());
        let visto = chave_vista
            .and_then(|chave| nova.cartoes.iter().position(|c| c.chave == chave))
            .or(nova.ativo())
            .unwrap_or(0);
        refazer_cartoes(j, &nova, agora);
        j.visto.set(visto);
    } else {
        for (grande, c) in j.cartoes.borrow().iter().zip(&nova.cartoes) {
            grande.mostrar_sessao(c);
        }
    }

    let nome = nova.nome.clone().unwrap_or_default();
    j.nome.set_label(&nome);
    j.avatar.set_text(Some(&nome));
    let dica: Vec<&str> = [nova.email.as_deref(), nova.computador.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    j.titulo.set_tooltip_text(Some(&dica.join("\n")));
    *j.carteira.borrow_mut() = Some(nova);

    if !na_tela(j, "carteira") {
        mostrar_tela(j, true);
    } else if refazer {
        rolar_para(j, j.visto.get(), false);
    }
    atualizar_controles(j);
}

fn refazer_cartoes(j: &Rc<Janela>, c: &Carteira, agora: u64) {
    for pagina in j.paginas.borrow_mut().drain(..) {
        j.carrossel.remove(&pagina);
    }
    let mut cartoes = j.cartoes.borrow_mut();
    cartoes.clear();
    let mut paginas = j.paginas.borrow_mut();
    for (i, cartao) in c.cartoes.iter().enumerate() {
        let grande = Grande::novo(cartao, i, agora);
        menu_do_cartao(&grande.raiz);
        let pagina = gtk::Box::builder()
            .halign(gtk::Align::Fill)
            .margin_top(10)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .build();
        pagina.append(&grande.raiz);
        j.carrossel.append(&pagina);
        paginas.push(pagina.upcast());
        cartoes.push(grande);
    }
}

/// Botão direito no cartão: as ações dele.
fn menu_do_cartao(raiz: &gtk::Box) {
    let modelo = gio::Menu::new();
    modelo.append(Some("Usar para assinar"), Some("win.usar"));
    modelo.append(Some("Detalhes"), Some("win.detalhes"));
    modelo.append(Some("Copiar número de série"), Some("win.copiar-serie"));
    let menu = gtk::PopoverMenu::from_model(Some(&modelo));
    menu.set_has_arrow(false);
    menu.set_halign(gtk::Align::Start);
    menu.set_parent(raiz);
    let clique = gtk::GestureClick::builder().button(3).build();
    clique.connect_pressed({
        let menu = menu.clone();
        move |_, _, x, y| {
            menu.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            menu.popup();
        }
    });
    raiz.add_controller(clique);
    raiz.connect_destroy(move |_| menu.unparent());
}

fn atualizar_controles(j: &Janela) {
    let carteira = j.carteira.borrow();
    let Some(c) = carteira.as_ref() else {
        j.acao_reautorizar.set_enabled(false);
        j.acao_usar.set_enabled(false);
        return;
    };
    let visto = j.visto.get();
    let ativo = c.ativo();
    let outro = ativo != Some(visto);
    j.usar.set_reveal_child(outro);
    j.acao_usar.set_enabled(outro);
    j.acao_reautorizar.set_enabled(
        ativo
            .and_then(|i| c.cartoes.get(i))
            .is_some_and(|a| matches!(a.sessao, Sessao::Aberta { .. })),
    );
    j.navegacao.set_visible(c.cartoes.len() > 1);
    j.anterior.set_sensitive(visto > 0);
    j.proximo.set_sensitive(visto + 1 < c.cartoes.len());
}

fn rolar_para(j: &Janela, i: usize, animar: bool) {
    if let Some(pagina) = j.paginas.borrow().get(i) {
        j.carrossel.scroll_to(pagina, animar);
    }
}

fn ir(j: &Janela, passo: isize) {
    let total = j.paginas.borrow().len();
    if total == 0 {
        return;
    }
    let novo = j.visto.get().saturating_add_signed(passo).min(total - 1);
    rolar_para(j, novo, true);
}

/// Troca entre a tela de entrar e a carteira.
fn mostrar_tela(j: &Rc<Janela>, carteira: bool) {
    j.pilha
        .set_visible_child_name(if carteira { "carteira" } else { "entrar" });
    j.titulo.set_visible(carteira);
    j.menu.set_visible(carteira);
    j.folha.set_reveal_bottom_bar(carteira);
    j.folha.set_can_open(carteira);
    if carteira {
        // O carrossel só tem tamanho depois que a página aparece.
        let alvo = j.visto.get();
        rolar_para(j, alvo, false);
        let fraca = Rc::downgrade(j);
        glib::idle_add_local_once(move || {
            if let Some(j) = fraca.upgrade() {
                rolar_para(&j, alvo, false);
            }
        });
    } else {
        j.folha.set_open(false);
    }
    focar(j);
    atualizar_controles(j);
}

/// O foco no que a tela pede: o campo de e-mail (o texto dentro da linha,
/// para a primeira tecla não se perder entrando nele) ou o carrossel. Antes
/// de a janela aparecer não há onde pôr o foco; `abrir` chama de novo.
fn focar(j: &Janela) {
    if na_tela(j, "carteira") {
        j.carrossel.grab_focus();
    } else if na_tela(j, "pin") {
        j.pin.grab_focus();
    } else {
        j.email.grab_focus();
    }
}

fn limpar_entrar(j: &Janela) {
    j.email.set_sensitive(true);
    j.senha.set_sensitive(true);
    j.senha.remove_css_class("error");
    j.erro.set_visible(false);
    j.botao_entrar.set_sensitive(true);
    j.botao_entrar.set_child(None::<&gtk::Widget>);
    j.botao_entrar.set_label("Entrar");
}

fn enviar(j: &Rc<Janela>) {
    let email = j.email.text().trim().to_string();
    let senha = j.senha.text().to_string();
    if j.entrando.get() || email.is_empty() || senha.is_empty() {
        return;
    }
    limpar_entrar(j);
    j.entrando.set(true);
    j.email.set_sensitive(false);
    j.senha.set_sensitive(false);
    j.botao_entrar.set_sensitive(false);
    j.botao_entrar.set_child(Some(&adw::Spinner::new()));
    let (computador, usuario) = remoteid::desta_maquina();
    let senha_do_pin = Zeroizing::new(senha.clone());
    em_segundo_plano(
        j,
        move |m| {
            let maquina = Maquina {
                nome: &computador,
                usuario_local: &usuario,
                dominio_rede: &computador,
            };
            m.preparar(&email, &senha, &maquina)
        },
        |j, resultado| {
            j.entrando.set(false);
            limpar_entrar(j);
            match resultado {
                Ok(no_chaveiro) => {
                    j.senha.set_text("");
                    if no_chaveiro {
                        recarregar(j);
                    } else {
                        // Sem chaveiro: a senha fica num arquivo cifrado com
                        // um PIN que a pessoa cria agora.
                        *j.senha_pendente.borrow_mut() = Some(senha_do_pin);
                        j.criando_pin.set(true);
                        j.pilha.set_visible_child_name("pin");
                        focar(j);
                    }
                }
                Err(e) => {
                    j.erro_texto.set_label(&e.to_string());
                    j.erro.set_visible(true);
                    j.senha.add_css_class("error");
                    j.senha.grab_focus();
                }
            }
        },
    );
}

/// O que falta para o PIN servir, ou `None` quando serve.
fn problema_do_pin(pin: &str, repetido: &str) -> Option<String> {
    if !pin::valido(pin) {
        return Some(format!(
            "De {} a {} números",
            pin::MIN_DIGITOS,
            pin::MAX_DIGITOS
        ));
    }
    (pin != repetido).then(|| "Os PINs não conferem".to_string())
}

fn guardar_pin(j: &Rc<Janela>) {
    let pin = Zeroizing::new(j.pin.text().to_string());
    if let Some(problema) = problema_do_pin(&pin, &j.pin_repetido.text()) {
        j.erro_pin_texto.set_label(&problema);
        j.erro_pin.set_visible(true);
        j.pin_repetido.add_css_class("error");
        return;
    }
    let Some(senha) = j.senha_pendente.borrow().clone() else {
        return;
    };
    j.botao_pin.set_sensitive(false);
    j.botao_pin.set_child(Some(&adw::Spinner::new()));
    em_segundo_plano(
        j,
        move |m| m.proteger_com_pin(&senha, &pin),
        |j, resultado| {
            j.botao_pin.set_child(None::<&gtk::Widget>);
            j.botao_pin.set_label("Guardar");
            j.botao_pin.set_sensitive(true);
            match resultado {
                Ok(()) => {
                    j.senha_pendente.take();
                    j.pin.set_text("");
                    j.pin_repetido.set_text("");
                    j.criando_pin.set(false);
                    recarregar(j);
                }
                Err(e) => {
                    j.erro_pin_texto.set_label(&e.to_string());
                    j.erro_pin.set_visible(true);
                }
            }
        },
    );
}

/// Sair é recuperável: a tela de entrar aparece na hora, com "Desfazer", e a
/// conta só sai do disco quando o aviso some.
fn sair(j: &Rc<Janela>) {
    if j.saindo.replace(true) {
        return;
    }
    limpar_entrar(j);
    j.email.set_text("");
    j.senha.set_text("");
    mostrar_tela(j, false);
    let aviso = adw::Toast::builder()
        .title("Saiu da conta")
        .button_label("Desfazer")
        .timeout(DESFAZER_S)
        .build();
    aviso.connect_button_clicked({
        let j = j.clone();
        move |_| {
            j.saindo.set(false);
            j.carteira.take();
            recarregar(&j);
        }
    });
    aviso.connect_dismissed({
        let j = j.clone();
        move |_| concluir_saida(&j)
    });
    j.toasts.add_toast(aviso);
}

fn concluir_saida(j: &Rc<Janela>) {
    if j.saindo.replace(false) {
        no_disco(j, Motor::sair);
    }
}

fn propriedade(titulo: &str, valor: &str) -> adw::ActionRow {
    adw::ActionRow::builder()
        .title(titulo)
        .subtitle(valor)
        .subtitle_selectable(true)
        .css_classes(["property"])
        .build()
}

fn lista() -> gtk::ListBox {
    gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build()
}

/// A folha de detalhes do cartão à vista: o certificado, a cadeia da raiz até
/// ele, e a conta.
fn montar_detalhes(j: &Janela) -> bool {
    let carteira = j.carteira.borrow();
    let Some(conta) = carteira.as_ref() else {
        return false;
    };
    let i = j.visto.get();
    let Some(c) = conta.cartoes.get(i) else {
        return false;
    };
    let agora = agora();
    let raiz = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(8)
        .margin_bottom(20)
        .margin_start(18)
        .margin_end(18)
        .build();
    raiz.append(&cartao::mini(
        &c.nome,
        &cartao::tipo(c.documento.as_ref()),
        i,
        c.alerta(agora),
    ));

    let certificado = lista();
    certificado.append(&propriedade("Emissor", &c.emissor));
    let serie = propriedade("Série", &c.serie);
    serie.add_suffix(
        &gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .action_name("win.copiar-serie")
            .tooltip_text("Copiar")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build(),
    );
    certificado.append(&serie);
    if let Some(v) = c.validade {
        let validade = propriedade("Validade", &cartao::data(v, "%d/%m/%Y"));
        if let Some(a) = cartao::alerta(c.alerta(agora)) {
            validade.add_suffix(&a);
        }
        certificado.append(&validade);
    }
    raiz.append(&certificado);

    if !c.autoridades.is_empty() {
        raiz.append(&texto("Cadeia", &["heading", "dim-label"]));
        let arvore = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(10)
            .margin_top(14)
            .margin_bottom(14)
            .margin_start(14)
            .margin_end(14)
            .hexpand(true)
            .build();
        let niveis = c
            .autoridades
            .iter()
            .rev()
            .map(String::as_str)
            .chain(Some(c.nome.as_str()));
        let total = c.autoridades.len() + 1;
        for (n, nome) in niveis.enumerate() {
            let linha = gtk::Box::builder()
                .spacing(8)
                .margin_start(n as i32 * 14)
                .build();
            if n > 0 {
                linha.append(&texto("↳", &["dim-label"]));
            }
            let titular = n + 1 == total;
            let icone = gtk::Image::from_icon_name(if titular {
                "object-select-symbolic"
            } else {
                "application-certificate-symbolic"
            });
            if titular {
                icone.add_css_class("success");
            }
            linha.append(&icone);
            let rotulo = texto(nome, if titular { &["heading"] } else { &[] });
            rotulo.set_wrap(true);
            rotulo.set_wrap_mode(gtk::pango::WrapMode::WordChar);
            rotulo.set_hexpand(true);
            linha.append(&rotulo);
            arvore.append(&linha);
        }
        let cartao_cadeia = gtk::Box::builder().css_classes(["card"]).build();
        cartao_cadeia.append(&arvore);
        raiz.append(&cartao_cadeia);
    }

    let dados_conta = lista();
    if let Some(email) = &conta.email {
        dados_conta.append(&propriedade("E-mail", email));
    }
    if let Some(computador) = &conta.computador {
        dados_conta.append(&propriedade("Computador", computador));
    }
    if dados_conta.first_child().is_some() {
        raiz.append(&texto("Conta", &["heading", "dim-label"]));
        raiz.append(&dados_conta);
    }

    j.folha.set_sheet(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_height(true)
            .max_content_height(580)
            .child(&raiz)
            .build(),
    ));
    true
}

fn acao(j: &Rc<Janela>, nome: &str, f: impl Fn(&Rc<Janela>) + 'static) -> gio::SimpleAction {
    let a = gio::SimpleAction::new(nome, None);
    let j = j.clone();
    a.connect_activate(move |_, _| f(&j));
    a
}

fn chave_vista(j: &Janela) -> Option<String> {
    j.carteira
        .borrow()
        .as_ref()?
        .cartoes
        .get(j.visto.get())
        .map(|c| c.chave.clone())
}

fn ligar(app: &adw::Application, j: &Rc<Janela>) {
    let w = &j.janela;
    j.acao_reautorizar.connect_activate({
        let j = j.clone();
        move |_, _| no_disco(&j, Motor::reautorizar_proxima)
    });
    w.add_action(&j.acao_reautorizar);
    j.acao_usar.connect_activate({
        let j = j.clone();
        move |_, _| {
            if let Some(chave) = chave_vista(&j) {
                no_disco(&j, |m| m.escolher_certificado(&chave));
            }
        }
    });
    w.add_action(&j.acao_usar);
    w.add_action(&acao(j, "sair", sair));
    w.add_action(&acao(j, "detalhes", |j| {
        if na_tela(j, "carteira") && montar_detalhes(j) {
            j.folha.set_open(true);
        }
    }));
    w.add_action(&acao(j, "copiar-serie", |j| {
        let serie = j
            .carteira
            .borrow()
            .as_ref()
            .and_then(|c| c.cartoes.get(j.visto.get()))
            .map(|c| c.serie.clone());
        if let Some(serie) = serie {
            j.janela.clipboard().set_text(&serie);
            j.toasts.add_toast(adw::Toast::new("Série copiada"));
        }
    }));
    w.add_action(&acao(j, "sobre", |j| {
        adw::AboutDialog::builder()
            .application_name(NOME)
            .application_icon(id_do_aplicativo())
            .developer_name("Âncora")
            .version(env!("CARGO_PKG_VERSION"))
            .license_type(gtk::License::Gpl30Only)
            .build()
            .present(Some(&j.janela));
    }));

    let fechar = gio::SimpleAction::new("quit", None);
    fechar.connect_activate({
        let app = app.clone();
        move |_, _| app.quit()
    });
    app.add_action(&fechar);
    app.set_accels_for_action("app.quit", &["<Ctrl>q"]);
    app.set_accels_for_action("window.close", &["<Ctrl>w"]);
    app.set_accels_for_action("win.reautorizar", &["<Ctrl>r"]);
    app.set_accels_for_action("win.detalhes", &["<Ctrl>d"]);
    app.set_accels_for_action("win.copiar-serie", &["<Ctrl><Shift>c"]);

    // Sair que ainda não chegou ao disco chega quando a janela fecha.
    w.connect_close_request({
        let j = j.clone();
        move |_| {
            concluir_saida(&j);
            glib::Propagation::Proceed
        }
    });
    app.connect_shutdown({
        let j = j.clone();
        move |_| concluir_saida(&j)
    });

    j.email.connect_entry_activated({
        let senha = j.senha.clone();
        move |_| {
            senha.grab_focus();
        }
    });
    j.senha.connect_entry_activated({
        let j = j.clone();
        move |_| enviar(&j)
    });
    j.botao_entrar.connect_clicked({
        let j = j.clone();
        move |_| enviar(&j)
    });
    j.senha.connect_changed({
        let j = j.clone();
        move |_| {
            j.senha.remove_css_class("error");
            j.erro.set_visible(false);
        }
    });

    let pin_mudou = {
        let j = j.clone();
        move || {
            j.erro_pin.set_visible(false);
            j.pin_repetido.remove_css_class("error");
            j.botao_pin
                .set_sensitive(problema_do_pin(&j.pin.text(), &j.pin_repetido.text()).is_none());
        }
    };
    j.pin.connect_changed({
        let f = pin_mudou.clone();
        move |_| f()
    });
    j.pin_repetido.connect_changed(move |_| pin_mudou());
    j.pin.connect_entry_activated({
        let repetido = j.pin_repetido.clone();
        move |_| {
            repetido.grab_focus();
        }
    });
    j.pin_repetido.connect_entry_activated({
        let j = j.clone();
        move |_| guardar_pin(&j)
    });
    j.botao_pin.connect_clicked({
        let j = j.clone();
        move |_| guardar_pin(&j)
    });

    j.carrossel.connect_page_changed({
        let j = j.clone();
        move |_, i| {
            j.visto.set(i as usize);
            atualizar_controles(&j);
        }
    });
    j.anterior.connect_clicked({
        let j = j.clone();
        move |_| ir(&j, -1)
    });
    j.proximo.connect_clicked({
        let j = j.clone();
        move |_| ir(&j, 1)
    });
    // A folha mostra o cartão à vista quando sobe pelo arrasto.
    j.folha.connect_open_notify({
        let j = j.clone();
        move |folha| {
            if folha.is_open() {
                montar_detalhes(&j);
            }
        }
    });

    // Setas trocam de cartão; Esc fecha a folha.
    let teclas = gtk::EventControllerKey::new();
    teclas.connect_key_pressed({
        let j = j.clone();
        move |_, tecla, _, _| {
            if j.folha.is_open() {
                if tecla == gtk::gdk::Key::Escape {
                    j.folha.set_open(false);
                    return glib::Propagation::Stop;
                }
                return glib::Propagation::Proceed;
            }
            if !na_tela(&j, "carteira") {
                return glib::Propagation::Proceed;
            }
            match tecla {
                gtk::gdk::Key::Left => ir(&j, -1),
                gtk::gdk::Key::Right => ir(&j, 1),
                _ => return glib::Propagation::Proceed,
            }
            glib::Propagation::Stop
        }
    });
    j.janela.add_controller(teclas);
}
