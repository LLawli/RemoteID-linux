//! Tela 2: Painel inicial (quando a instalação está preparada).
//!
//! Apresenta a identidade do titular, certificados disponíveis na carteira,
//! o estado da próxima assinatura em linguagem humana (com base nas sessões em cache)
//! e a ação de reautorizar.

use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::modelo::EstadoApp;

/// Ações disponíveis a partir do painel principal.
#[derive(Clone)]
pub struct AcoesPainel {
    pub abrir_configuracoes: Rc<dyn Fn()>,
    pub trocar_certificado: Rc<dyn Fn()>,
    pub reautorizar: Rc<dyn Fn()>,
}

/// Monta o conteúdo do painel principal da aplicação.
pub fn montar(estado: &EstadoApp, acoes: AcoesPainel) -> gtk::Widget {
    let clamp = adw::Clamp::builder()
        .maximum_size(620)
        .margin_top(16)
        .margin_bottom(24)
        .margin_start(16)
        .margin_end(16)
        .build();

    let pagina = adw::PreferencesPage::new();

    // 1. Grupo Identidade
    let grupo_identidade = adw::PreferencesGroup::builder().title("Identidade").build();

    let (nome_titular, doc_titular) = estado.nome_e_documento_titular();
    let linha_titular = match doc_titular {
        Some(doc) => adw::ActionRow::builder()
            .title(&nome_titular)
            .subtitle(&doc)
            .build(),
        None => adw::ActionRow::builder()
            .title("Titular")
            .subtitle(&nome_titular)
            .build(),
    };
    linha_titular.add_prefix(&gtk::Image::from_icon_name("avatar-default-symbolic"));
    grupo_identidade.add(&linha_titular);

    if let Some(codigo) = &estado.codigo_desktop {
        let linha_desktop = adw::ActionRow::builder()
            .title("Código do computador")
            .subtitle(codigo)
            .build();
        linha_desktop.add_prefix(&gtk::Image::from_icon_name("computer-symbolic"));

        let botao_copiar = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text("Copiar código do computador")
            .css_classes(["flat"])
            .build();

        let cod_clonado = codigo.clone();
        botao_copiar.connect_clicked(move |btn| {
            if let Some(display) = gtk::gdk::Display::default() {
                display.clipboard().set_text(&cod_clonado);
                btn.set_tooltip_text(Some("Copiado!"));
            }
        });

        linha_desktop.add_suffix(&botao_copiar);
        grupo_identidade.add(&linha_desktop);
    }
    pagina.add(&grupo_identidade);

    // 2. Grupo Certificados
    let grupo_certificados = adw::PreferencesGroup::builder()
        .title("Certificados")
        .build();

    let multi_cert = estado.certificados.len() > 1;
    let cert_ativo = estado.certificado_ativo_ou_primeiro();

    for cert in &estado.certificados {
        let e_ativo = cert_ativo.is_some_and(|a| a.key_name == cert.key_name);

        let (nome_cert, _) = cert.nome_e_documento();
        let validade_str = cert.validade.as_deref().unwrap_or("Não informada");
        let sub = format!(
            "{} • Série {} • Válido até {}",
            cert.emissor, cert.serial, validade_str
        );
        let linha_cert = adw::ExpanderRow::builder()
            .title(&nome_cert)
            .subtitle(&sub)
            .expanded(false)
            .build();

        if e_ativo {
            let icone_ativo = gtk::Image::builder()
                .icon_name("emblem-ok-symbolic")
                .tooltip_text("Certificado padrão para assinaturas")
                .build();
            linha_cert.add_prefix(&icone_ativo);
        } else {
            let icone_outro = gtk::Image::from_icon_name("application-certificate-symbolic");
            linha_cert.add_prefix(&icone_outro);
        }

        let texto_validade = match &cert.validade {
            Some(v) => format!("Válido até {v}"),
            None => "Não informada".to_string(),
        };

        let linha_val = adw::ActionRow::builder()
            .title("Validade")
            .subtitle(&texto_validade)
            .build();
        linha_val.add_prefix(&gtk::Image::from_icon_name("x-office-calendar-symbolic"));
        linha_cert.add_row(&linha_val);

        if !cert.ous.is_empty() {
            let ous_texto = cert.ous.join(" • ");
            let linha_ou = adw::ActionRow::builder()
                .title("Unidades Organizacionais")
                .subtitle(&ous_texto)
                .build();
            linha_ou.add_prefix(&gtk::Image::from_icon_name("system-users-symbolic"));
            linha_cert.add_row(&linha_ou);
        }

        grupo_certificados.add(&linha_cert);
    }

    if multi_cert {
        let linha_trocar = adw::ActionRow::builder()
            .title("Trocar certificado padrão")
            .subtitle("Escolha outro certificado da carteira para assinaturas")
            .activatable(true)
            .build();
        linha_trocar.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

        let acoes_clone = acoes.clone();
        linha_trocar.connect_activated(move |_| {
            (acoes_clone.trocar_certificado)();
        });
        grupo_certificados.add(&linha_trocar);
    }
    pagina.add(&grupo_certificados);

    // 3. Grupo Assinatura
    let grupo_assinatura = adw::PreferencesGroup::builder().title("Assinatura").build();

    let cert_key_ativo = cert_ativo.map(|c| c.key_name.as_str());
    let sessao_ativa = estado
        .sessoes
        .iter()
        .find(|s| cert_key_ativo.is_some_and(|k| s.cert_key == k || k.starts_with(&s.cert_key)));

    let (texto_status_assinatura, tem_sessao) = match sessao_ativa {
        Some(s) => {
            if let Some(emitido) = s.emitido_em {
                // TTL padrão considerado: 15 minutos (900s)
                let expira_em = emitido + 15 * 60;
                if let Ok(dt) = glib::DateTime::from_unix_local(expira_em as i64) {
                    if let Ok(hora) = dt.format("%H:%M") {
                        (
                            format!("Sessão ativa até às {hora} (não pedirá PIN nem OTP)"),
                            true,
                        )
                    } else {
                        (
                            "Sessão em cache ativa (não pedirá PIN nem OTP)".to_string(),
                            true,
                        )
                    }
                } else {
                    (
                        "Sessão em cache ativa (não pedirá PIN nem OTP)".to_string(),
                        true,
                    )
                }
            } else {
                (
                    "Sessão em cache ativa (não pedirá PIN nem OTP)".to_string(),
                    true,
                )
            }
        }
        None => (
            "Nenhuma sessão ativa. A próxima assinatura pedirá PIN e OTP.".to_string(),
            false,
        ),
    };

    let linha_assinatura = adw::ActionRow::builder()
        .title("Próxima assinatura")
        .subtitle(&texto_status_assinatura)
        .build();

    let icone_status = if tem_sessao {
        "security-high-symbolic"
    } else {
        "channel-insecure-symbolic"
    };
    linha_assinatura.add_prefix(&gtk::Image::from_icon_name(icone_status));

    let botao_reaut = gtk::Button::builder()
        .label("Reautorizar")
        .valign(gtk::Align::Center)
        .tooltip_text("Descarta a sessão em cache para pedir PIN e OTP na próxima assinatura")
        .build();

    let acoes_clone = acoes;
    botao_reaut.connect_clicked(move |_| {
        (acoes_clone.reautorizar)();
    });

    linha_assinatura.add_suffix(&botao_reaut);
    grupo_assinatura.add(&linha_assinatura);
    pagina.add(&grupo_assinatura);

    clamp.set_child(Some(&pagina));
    clamp.upcast::<gtk::Widget>()
}

/// Cria uma janela completa de preview para o painel principal.
pub fn criar_janela_preview() -> gtk::Window {
    let estado = EstadoApp::mock_preparado();
    let acoes = AcoesPainel {
        abrir_configuracoes: Rc::new(|| {
            println!("[PREVIEW] Painel: abrir configurações");
        }),
        trocar_certificado: Rc::new(|| {
            println!("[PREVIEW] Painel: trocar certificado");
        }),
        reautorizar: Rc::new(|| {
            println!("[PREVIEW] Painel: reautorizar clicado");
        }),
    };

    let cabecalho = adw::HeaderBar::new();
    let botao_cfg = gtk::Button::builder()
        .icon_name("preferences-system-symbolic")
        .tooltip_text("Configurações")
        .build();
    let acoes_cfg = acoes.clone();
    botao_cfg.connect_clicked(move |_| (acoes_cfg.abrir_configuracoes)());
    cabecalho.pack_end(&botao_cfg);

    let barra = adw::ToolbarView::new();
    barra.add_top_bar(&cabecalho);
    barra.set_content(Some(&montar(&estado, acoes)));

    let janela = adw::Window::builder()
        .title("Preview: Painel Inicial")
        .default_width(520)
        .default_height(640)
        .content(&barra)
        .build();

    janela.upcast::<gtk::Window>()
}
