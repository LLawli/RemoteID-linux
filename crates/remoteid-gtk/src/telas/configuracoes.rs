//! Tela 4: Configurações do aplicativo.
//!
//! Permite ajustar o cache de PIN, TTL de sessão, nome da aplicação,
//! inspecionar pasta de diagnóstico e executar a reinstalação (zona de perigo).

use std::rc::Rc;

use adw::prelude::*;

use crate::modelo::{Certificado, ConfigApp};

/// Ações disponíveis na tela de configurações.
#[derive(Clone)]
pub struct AcoesConfiguracoes {
    pub voltar: Rc<dyn Fn()>,
    pub salvar: Rc<dyn Fn(ConfigApp)>,
    pub trocar_certificado: Option<Rc<dyn Fn()>>,
    pub reinstalar: Rc<dyn Fn()>,
}

/// Monta o widget da tela de configurações.
pub fn montar(
    config: &ConfigApp,
    cert_ativo: Option<&Certificado>,
    multi_cert: bool,
    acoes: AcoesConfiguracoes,
) -> gtk::Widget {
    let clamp = adw::Clamp::builder()
        .maximum_size(620)
        .margin_top(16)
        .margin_bottom(24)
        .margin_start(16)
        .margin_end(16)
        .build();

    let pagina = adw::PreferencesPage::new();

    // 1. Grupo Segurança & Sessão
    let grupo_sessao = adw::PreferencesGroup::builder()
        .title("Segurança & Sessão")
        .build();

    let linha_pin = adw::SpinRow::builder()
        .title("Cache do PIN (minutos)")
        .subtitle("0 desativa o cache; caso contrário, o PIN não é repedido dentro do intervalo")
        .adjustment(&gtk::Adjustment::new(
            config.cache_pin_min as f64,
            0.0,
            60.0,
            1.0,
            5.0,
            0.0,
        ))
        .build();
    grupo_sessao.add(&linha_pin);

    let linha_ttl = adw::SpinRow::builder()
        .title("TTL da sessão (minutos)")
        .subtitle("Intervalo para reutilizar a sessão de assinatura antes de solicitar novo OTP")
        .adjustment(&gtk::Adjustment::new(
            config.ttl_sessao_min as f64,
            1.0,
            120.0,
            1.0,
            5.0,
            0.0,
        ))
        .build();
    grupo_sessao.add(&linha_ttl);

    let linha_nome = adw::EntryRow::builder()
        .title("Nome da aplicação")
        .text(&config.nome_aplicacao)
        .build();
    grupo_sessao.add(&linha_nome);
    pagina.add(&grupo_sessao);

    // 2. Grupo Certificado (se houver múltiplos)
    if multi_cert {
        let grupo_cert = adw::PreferencesGroup::builder()
            .title("Certificado de Assinatura")
            .build();

        let sub = match cert_ativo {
            Some(c) => format!("{} (Série {})", c.titular, c.serial),
            None => "Nenhum selecionado".to_string(),
        };

        let linha_trocar = adw::ActionRow::builder()
            .title("Certificado padrão")
            .subtitle(&sub)
            .activatable(true)
            .build();
        linha_trocar.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

        if let Some(ref cb_trocar) = acoes.trocar_certificado {
            let cb = cb_trocar.clone();
            linha_trocar.connect_activated(move |_| cb());
        }

        grupo_cert.add(&linha_trocar);
        pagina.add(&grupo_cert);
    }

    // 3. Grupo Diagnóstico
    let grupo_diag = adw::PreferencesGroup::builder()
        .title("Diagnóstico")
        .build();

    let linha_diag = adw::ActionRow::builder()
        .title("Pasta de registros (logs)")
        .subtitle(&config.caminho_log)
        .build();

    let botao_abrir_pasta = gtk::Button::builder()
        .icon_name("folder-open-symbolic")
        .valign(gtk::Align::Center)
        .tooltip_text("Abrir pasta de registros")
        .css_classes(["flat"])
        .build();

    let caminho_clonado = config.caminho_log.clone();
    botao_abrir_pasta.connect_clicked(move |_| {
        let uri = if caminho_clonado.starts_with('/') {
            format!("file://{caminho_clonado}")
        } else {
            let expandido = shellexpand::tilde(&caminho_clonado).to_string();
            format!("file://{expandido}")
        };
        let _ = gtk::gio::AppInfo::launch_default_for_uri(&uri, None::<&gtk::gio::AppLaunchContext>);
    });

    linha_diag.add_suffix(&botao_abrir_pasta);
    grupo_diag.add(&linha_diag);
    pagina.add(&grupo_diag);

    // 4. Grupo Zona de Perigo
    let grupo_perigo = adw::PreferencesGroup::builder()
        .title("Zona de Perigo")
        .build();

    let linha_reinstalar = adw::ActionRow::builder()
        .title("Reinstalar aplicação")
        .subtitle("Apaga a chave da instalação e o estado local. Os logs serão preservados.")
        .build();

    let botao_reinstalar = gtk::Button::builder()
        .label("Reinstalar")
        .valign(gtk::Align::Center)
        .css_classes(["destructive-action"])
        .build();

    {
        let acoes_clone = acoes.clone();
        botao_reinstalar.connect_clicked(move |btn| {
            let janela_pai = btn.root().and_downcast::<gtk::Window>();

            let dialogo = adw::MessageDialog::builder()
                .heading("Reinstalar RemoteID?")
                .body(
                    "Esta ação removerá a chave de identificação do desktop e todos os certificados locais.\n\
                     Você precisará fazer login e registrar o computador novamente.",
                )
                .build();

            if let Some(ref pai) = janela_pai {
                dialogo.set_transient_for(Some(pai));
            }

            dialogo.add_response("cancelar", "Cancelar");
            dialogo.add_response("reinstalar", "Reinstalar");
            dialogo.set_response_appearance("reinstalar", adw::ResponseAppearance::Destructive);
            dialogo.set_default_response(Some("cancelar"));
            dialogo.set_close_response("cancelar");

            let acoes_reinstalar = acoes_clone.clone();
            dialogo.connect_response(None, move |_, resp| {
                if resp == "reinstalar" {
                    (acoes_reinstalar.reinstalar)();
                }
            });

            dialogo.present();
        });
    }

    linha_reinstalar.add_suffix(&botao_reinstalar);
    grupo_perigo.add(&linha_reinstalar);
    pagina.add(&grupo_perigo);

    // Salvar ao disparar ação
    let caminho_salvo = config.caminho_log.clone();
    let acoes_salvar = acoes.clone();
    let l_pin = linha_pin.clone();
    let l_ttl = linha_ttl.clone();
    let l_nome = linha_nome.clone();

    // Ações de salvar podem ser acionadas pela barra superior (HeaderBar)
    let _salvar_closure = move || {
        let nova_cfg = ConfigApp {
            cache_pin_min: l_pin.value() as u32,
            ttl_sessao_min: l_ttl.value() as u32,
            nome_aplicacao: l_nome.text().to_string(),
            caminho_log: caminho_salvo.clone(),
        };
        (acoes_salvar.salvar)(nova_cfg);
    };

    clamp.set_child(Some(&pagina));
    clamp.upcast::<gtk::Widget>()
}

/// Cria uma janela de preview para a tela de configurações.
pub fn criar_janela_preview() -> gtk::Window {
    let config = ConfigApp::mock();
    let cert_ativo = Certificado {
        titular: "MARIA SILVA:12345678900".to_string(),
        emissor: "AC OAB G3".to_string(),
        serial: "3A:1F:9C:22:04:8B".to_string(),
        key_name: "3A1F9C22048B;CN=AC OAB G3".to_string(),
        ous: vec!["Autenticado por Certisign".to_string(), "Advogado".to_string()],
        validade: Some("14/09/2027".to_string()),
    };

    let acoes = AcoesConfiguracoes {
        voltar: Rc::new(|| {
            println!("[PREVIEW] Configurações: Voltar clicado");
        }),
        salvar: Rc::new(|cfg| {
            println!("[PREVIEW] Configurações: Salvar clicado: {:?}", cfg);
        }),
        trocar_certificado: Some(Rc::new(|| {
            println!("[PREVIEW] Configurações: Trocar certificado clicado");
        })),
        reinstalar: Rc::new(|| {
            println!("[PREVIEW] Configurações: Reinstalar confirmado");
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
    barra.set_content(Some(&montar(&config, Some(&cert_ativo), true, acoes)));

    let janela = adw::Window::builder()
        .title("Preview: Configurações")
        .default_width(520)
        .default_height(640)
        .content(&barra)
        .build();

    janela.upcast::<gtk::Window>()
}

mod shellexpand {
    pub fn tilde(path: &str) -> String {
        if let Some(rest) = path.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return format!("{home}/{rest}");
            }
        }
        path.to_string()
    }
}
