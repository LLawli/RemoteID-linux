//! Tela 3: Seleção do certificado padrão (quando a carteira possui múltiplos certificados).
//!
//! Permite ao usuário escolher qual certificado usar como padrão nas assinaturas.
//! A escolha é persistida pelo serviço (`Requisicao::EscolherCertificado`).

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;

use crate::modelo::EstadoApp;

/// Ações disponíveis na tela de seleção de certificado.
#[derive(Clone)]
pub struct AcoesSelecao {
    pub voltar: Rc<dyn Fn()>,
    pub confirmar: Rc<dyn Fn(String)>,
}

/// Monta o widget de seleção de certificado.
pub fn montar(estado: &EstadoApp, acoes: AcoesSelecao) -> gtk::Widget {
    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .margin_top(16)
        .margin_bottom(24)
        .margin_start(16)
        .margin_end(16)
        .build();

    let caixa_vertical = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .build();

    let grupo = adw::PreferencesGroup::builder()
        .title("Certificados na Carteira")
        .description("Selecione o certificado padrão para ser utilizado nas assinaturas digitais.")
        .build();

    let cert_ativo = estado.certificado_ativo_ou_primeiro();
    let selecionado_key = Rc::new(RefCell::new(
        cert_ativo.map(|c| c.key_name.clone()).unwrap_or_default(),
    ));

    let mut primeiro_radio: Option<gtk::CheckButton> = None;

    for cert in &estado.certificados {
        let e_ativo = cert_ativo.is_some_and(|a| a.key_name == cert.key_name);

        let (nome, doc) = cert.nome_e_documento();
        let sub = match doc {
            Some(cpf) => format!("{cpf} • {} • Série {}", cert.emissor, cert.serial),
            None => format!("{} • Série {}", cert.emissor, cert.serial),
        };
        let linha = adw::ActionRow::builder()
            .title(&nome)
            .subtitle(&sub)
            .activatable(true)
            .build();

        let radio = gtk::CheckButton::builder()
            .active(e_ativo)
            .valign(gtk::Align::Center)
            .build();

        if let Some(ref primeiro) = primeiro_radio {
            radio.set_group(Some(primeiro));
        } else {
            primeiro_radio = Some(radio.clone());
        }

        linha.set_activatable_widget(Some(&radio));
        linha.add_prefix(&radio);

        let kn = cert.key_name.clone();
        let sel_ref = selecionado_key.clone();
        radio.connect_toggled(move |btn| {
            if btn.is_active() {
                *sel_ref.borrow_mut() = kn.clone();
            }
        });

        grupo.add(&linha);
    }

    caixa_vertical.append(&grupo);

    let botao_confirmar = gtk::Button::builder()
        .label("Definir como padrão")
        .halign(gtk::Align::Center)
        .css_classes(["pill", "suggested-action"])
        .margin_top(12)
        .build();

    {
        let acoes_clone = acoes;
        let sel_ref = selecionado_key;
        botao_confirmar.connect_clicked(move |_| {
            let escolhido = sel_ref.borrow().clone();
            if !escolhido.is_empty() {
                (acoes_clone.confirmar)(escolhido);
            }
        });
    }

    caixa_vertical.append(&botao_confirmar);
    clamp.set_child(Some(&caixa_vertical));
    clamp.upcast::<gtk::Widget>()
}

/// Cria uma janela de preview para a seleção de certificado.
pub fn criar_janela_preview() -> gtk::Window {
    let estado = EstadoApp::mock_multi_token();
    let acoes = AcoesSelecao {
        voltar: Rc::new(|| {
            println!("[PREVIEW] Seleção: Voltar clicado");
        }),
        confirmar: Rc::new(|key| {
            println!("[PREVIEW] Seleção: Confirmar clicado para {key}");
        }),
    };

    let cabecalho = adw::HeaderBar::new();
    let botao_voltar = gtk::Button::builder()
        .icon_name("go-previous-symbolic")
        .tooltip_text("Voltar")
        .build();
    let acoes_voltar = acoes.clone();
    botao_voltar.connect_clicked(move |_| (acoes_voltar.voltar)());
    cabecalho.pack_start(&botao_voltar);

    let barra = adw::ToolbarView::new();
    barra.add_top_bar(&cabecalho);
    barra.set_content(Some(&montar(&estado, acoes)));

    let janela = adw::Window::builder()
        .title("Preview: Seleção de Certificado")
        .default_width(520)
        .default_height(600)
        .content(&barra)
        .build();

    janela.upcast::<gtk::Window>()
}
