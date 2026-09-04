//! Diálogo modal para solicitação de PIN e OTP na assinatura.
//!
//! Exibido sob demanda pelo `Prompter` quando um `C_Sign` do módulo PKCS#11
//! precisa de autorização interativa.
//!
//! Atende estritamente às regras do Wayland/Hyprland (diálogo flutuante modal,
//! não redimensionável, dimensões fixas) e executa um `glib::MainLoop` local
//! aninhado para aguardar a resposta sem travar a thread de interface.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use remoteid_autorizacao::Fatores;
use remoteid_tipos::{Error, Result};

use crate::modelo::separar_nome_e_documento;

/// Estrutura contendo os widgets montados do diálogo.
pub struct WidgetsPinOtp {
    pub raiz: gtk::Widget,
    pub campo_pin: adw::PasswordEntryRow,
    pub campo_otp: adw::EntryRow,
    pub botao_assinar: gtk::Button,
    pub botao_cancelar: gtk::Button,
}

/// Monta a interface de PIN e OTP com as restrições dimensionais e regras de validação.
pub fn montar(
    titular: Option<&str>,
    hospedeiro: Option<&str>,
    pin_inicial: Option<&str>,
) -> WidgetsPinOtp {
    let clamp = adw::Clamp::builder()
        .maximum_size(380)
        .margin_top(20)
        .margin_bottom(20)
        .margin_start(20)
        .margin_end(20)
        .build();

    let caixa_vertical = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .halign(gtk::Align::Fill)
        .build();

    let (nome_titular, doc_titular) = match titular {
        Some(t) if !t.is_empty() => {
            let (nome, doc) = separar_nome_e_documento(t);
            let titulo = if nome.is_empty() {
                "Autorizar assinatura".to_string()
            } else {
                format!("Assinar como {nome}")
            };
            (titulo, doc)
        }
        _ => ("Autorizar assinatura".to_string(), None),
    };

    let subtitulo = match (doc_titular, hospedeiro.filter(|h| !h.is_empty())) {
        (Some(doc), Some(host)) => Some(format!("{doc} • Solicitado por {host}")),
        (Some(doc), None) => Some(doc),
        (None, Some(host)) => Some(format!("Solicitado por {host}")),
        (None, None) => None,
    };

    let cabecalho = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .halign(gtk::Align::Center)
        .margin_bottom(4)
        .build();

    let rotulo_titulo = gtk::Label::builder()
        .label(&nome_titular)
        .halign(gtk::Align::Center)
        .justify(gtk::Justification::Center)
        .css_classes(["title-3"])
        .wrap(true)
        .build();
    cabecalho.append(&rotulo_titulo);

    if let Some(sub) = subtitulo {
        let rotulo_sub = gtk::Label::builder()
            .label(&sub)
            .halign(gtk::Align::Center)
            .justify(gtk::Justification::Center)
            .css_classes(["dim-label"])
            .wrap(true)
            .build();
        cabecalho.append(&rotulo_sub);
    }
    caixa_vertical.append(&cabecalho);

    let grupo_campos = adw::PreferencesGroup::builder()
        .margin_top(4)
        .margin_bottom(4)
        .build();

    let campo_pin = adw::PasswordEntryRow::builder()
        .title("PIN do Certificado")
        .activates_default(true)
        .build();

    if let Some(pin) = pin_inicial {
        campo_pin.set_text(pin);
    }

    let campo_otp = adw::EntryRow::builder()
        .title("Código OTP (6 dígitos)")
        .activates_default(true)
        .input_purpose(gtk::InputPurpose::Digits)
        .build();

    // Remove o ícone de lápis das linhas de entrada
    esconder_icones_edicao(&campo_pin);
    esconder_icones_edicao(&campo_otp);

    // CSS global garantindo que o ícone de lápis embutido não seja desenhado nem ocupe espaço
    garantir_css_sem_icone_edicao();

    grupo_campos.add(&campo_pin);
    grupo_campos.add(&campo_otp);
    caixa_vertical.append(&grupo_campos);

    let botoes = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .homogeneous(true)
        .halign(gtk::Align::Fill)
        .margin_top(18)
        .build();

    let botao_cancelar = gtk::Button::builder()
        .label("Cancelar")
        .css_classes(["pill"])
        .height_request(42)
        .build();

    let botao_assinar = gtk::Button::builder()
        .label("Assinar")
        .css_classes(["pill", "suggested-action"])
        .height_request(42)
        .sensitive(false)
        .build();

    botoes.append(&botao_cancelar);
    botoes.append(&botao_assinar);
    caixa_vertical.append(&botoes);

    clamp.set_child(Some(&caixa_vertical));

    // O botão "Assinar" só fica ativo se tanto PIN quanto OTP estiverem preenchidos.
    let atualizar_botao = {
        let botao = botao_assinar.clone();
        let pin = campo_pin.clone();
        let otp = campo_otp.clone();
        move || {
            let pronto = !pin.text().is_empty() && !otp.text().is_empty();
            botao.set_sensitive(pronto);
        }
    };

    atualizar_botao();
    {
        let cb = atualizar_botao.clone();
        campo_pin.connect_changed(move |_| cb());
    }
    {
        let cb = atualizar_botao;
        campo_otp.connect_changed(move |_| cb());
    }

    WidgetsPinOtp {
        raiz: clamp.upcast::<gtk::Widget>(),
        campo_pin,
        campo_otp,
        botao_assinar,
        botao_cancelar,
    }
}

/// Injeta regra CSS global para suprimir o ícone de lápis nas linhas AdwEntryRow.
fn garantir_css_sem_icone_edicao() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let provedor = gtk::CssProvider::new();
        provedor.load_from_data(
            "image.edit-icon, .edit-icon { opacity: 0; min-width: 0; min-height: 0; padding: 0; margin: 0; -gtk-icon-size: 0px; }",
        );
        if let Some(display) = gtk::gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provedor,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });
}

/// Oculta recursivamente quaisquer nós que possuam a classe de edição (ícone de lápis).
fn esconder_icones_edicao(raiz: &impl IsA<gtk::Widget>) {
    let mut proximo = raiz.first_child();
    while let Some(w) = proximo {
        if w.has_css_class("edit-icon") {
            w.set_visible(false);
        }
        esconder_icones_edicao(&w);
        proximo = w.next_sibling();
    }
}

/// Cria a janela flutuante obedecendo aos parâmetros para compositores Wayland/Hyprland.
pub fn criar_janela_dialogo(
    janela_pai: Option<&gtk::Window>,
    widgets: &WidgetsPinOtp,
) -> gtk::Window {
    let janela = gtk::Window::builder()
        .title("RemoteID — autorizar assinatura")
        .modal(true)
        .resizable(false)
        .default_width(400)
        .default_height(290)
        .child(&widgets.raiz)
        .build();

    if let Some(pai) = janela_pai {
        janela.set_transient_for(Some(pai));
    }

    janela.set_default_widget(Some(&widgets.botao_assinar));
    janela
}

/// Executa o diálogo de PIN/OTP modalmente usando um `glib::MainLoop` aninhado.
///
/// Bloqueia a execução síncrona até o usuário confirmar ("Assinar") ou cancelar,
/// processando os eventos do GTK normalmente sem congelar a interface.
pub fn rodar_modal(
    janela_pai: Option<&gtk::Window>,
    titular: Option<&str>,
    hospedeiro: Option<&str>,
    pin_inicial: Option<&str>,
) -> Result<Fatores> {
    if let Err(e) = gtk::init() {
        return Err(Error::uso(format!(
            "GTK não pôde ser inicializado (sessão gráfica ausente?): {e}"
        )));
    }

    let widgets = montar(titular, hospedeiro, pin_inicial);
    let janela = criar_janela_dialogo(janela_pai, &widgets);

    let resultado: Rc<RefCell<Option<Result<Fatores>>>> = Rc::new(RefCell::new(None));
    let loop_local = glib::MainLoop::new(None, false);

    // Ação: Assinar
    {
        let resultado = resultado.clone();
        let loop_local = loop_local.clone();
        let campo_pin = widgets.campo_pin.clone();
        let campo_otp = widgets.campo_otp.clone();
        widgets.botao_assinar.connect_clicked(move |_| {
            let pin = campo_pin.text().to_string();
            let otp = campo_otp.text().to_string();
            *resultado.borrow_mut() = Some(Ok(Fatores::PinOtp { pin, otp }));
            loop_local.quit();
        });
    }

    // Ação: Cancelar
    {
        let resultado = resultado.clone();
        let loop_local = loop_local.clone();
        widgets.botao_cancelar.connect_clicked(move |_| {
            *resultado.borrow_mut() = Some(Err(Error::uso("cancelado pelo usuário no diálogo")));
            loop_local.quit();
        });
    }

    // Ação: Fechamento da janela pelo gerenciador de janelas
    {
        let resultado = resultado.clone();
        let loop_local = loop_local.clone();
        janela.connect_close_request(move |_| {
            if resultado.borrow().is_none() {
                *resultado.borrow_mut() =
                    Some(Err(Error::uso("cancelado pelo usuário no diálogo")));
            }
            loop_local.quit();
            glib::Propagation::Proceed
        });
    }

    janela.present();

    // Se o PIN já veio preenchido, foca diretamente o campo do OTP
    if pin_inicial.is_some_and(|p| !p.is_empty()) {
        widgets.campo_otp.grab_focus();
    } else {
        widgets.campo_pin.grab_focus();
    }

    // Roda o loop aninhado seguro
    loop_local.run();
    janela.close();

    // Drena eventos pendentes no contexto do GLib antes de retornar
    let ctx = glib::MainContext::default();
    while ctx.iteration(false) {}

    let saida = resultado
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err(Error::uso("cancelado pelo usuário no diálogo")));
    saida
}

/// Cria uma janela de preview para inspeção estática no modo `--preview`.
pub fn criar_janela_preview(titular: &str, hospedeiro: &str) -> gtk::Window {
    let widgets = montar(Some(titular), Some(hospedeiro), Some("1234"));
    widgets.botao_assinar.connect_clicked(|_| {
        println!("[PREVIEW] Diálogo PIN/OTP: botão 'Assinar' clicado");
    });
    widgets.botao_cancelar.connect_clicked(|_| {
        println!("[PREVIEW] Diálogo PIN/OTP: botão 'Cancelar' clicado");
    });

    gtk::Window::builder()
        .title("Preview: Diálogo PIN/OTP")
        .resizable(false)
        .default_width(400)
        .default_height(290)
        .child(&widgets.raiz)
        .build()
}
