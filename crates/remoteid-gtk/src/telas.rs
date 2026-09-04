//! As telas, cada uma uma função que devolve um widget a partir de um modelo.
//!
//! As ações (o que acontece ao clicar) chegam como closures em structs
//! `Acoes*`, para o mesmo desenho servir tanto a janela real (que fala com o
//! socket) quanto o `--preview` (que só registra no stdout). Nenhuma tela
//! conhece socket ou protocolo.

use std::rc::Rc;

use adw::prelude::*;

use crate::modelo::{Certificado, ConfigApp, EstadoApp};

/// Helpers de layout comuns às telas.
mod comum {
    use gtk::prelude::*;

    /// Uma raiz de tela vertical, com margens folgadas e um título.
    pub fn pagina(titulo: &str, subtitulo: Option<&str>) -> gtk::Box {
        let raiz = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(14)
            .margin_top(22)
            .margin_bottom(22)
            .margin_start(22)
            .margin_end(22)
            .build();
        let t = gtk::Label::builder()
            .label(titulo)
            .halign(gtk::Align::Start)
            .css_classes(["title-2"])
            .build();
        raiz.append(&t);
        if let Some(sub) = subtitulo {
            let s = gtk::Label::builder()
                .label(sub)
                .halign(gtk::Align::Start)
                .wrap(true)
                .xalign(0.0)
                .css_classes(["dim-label"])
                .build();
            raiz.append(&s);
        }
        raiz
    }

    /// Um "cartão" com moldura, para agrupar informação.
    pub fn cartao() -> gtk::Box {
        gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .css_classes(["card"])
            .margin_top(4)
            .build()
    }

    /// Uma linha "rótulo: valor" para o painel de status.
    pub fn linha(rotulo: &str, valor: &str) -> gtk::Box {
        let linha = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .margin_top(4)
            .margin_bottom(4)
            .margin_start(10)
            .margin_end(10)
            .build();
        let r = gtk::Label::builder()
            .label(rotulo)
            .halign(gtk::Align::Start)
            .width_chars(16)
            .xalign(0.0)
            .css_classes(["dim-label"])
            .build();
        let v = gtk::Label::builder()
            .label(valor)
            .halign(gtk::Align::Start)
            .hexpand(true)
            .xalign(0.0)
            .wrap(true)
            .selectable(true)
            .build();
        linha.append(&r);
        linha.append(&v);
        linha
    }
}

// ---------------------------------------------------------------------------
// Tela: Login / instalação (o wizard de preparação)
// ---------------------------------------------------------------------------

/// Ações da tela de login.
pub struct AcoesLogin {
    /// Chamada com (email, senha) ao clicar "Preparar". A janela real repassa
    /// isso ao CLI `remoteid preparar` via variáveis de ambiente (nunca por
    /// argumento, que fica visível em `ps`).
    pub preparar: Rc<dyn Fn(String, String)>,
}

/// Tela de primeiro uso: coleta e-mail e senha do RemoteID para preparar a
/// instalação (login + registro do desktop + carteira).
///
/// libadwaita: uma [`adw::StatusPage`] de boas-vindas com o formulário (um
/// [`adw::PreferencesGroup`] com [`adw::EntryRow`]/[`adw::PasswordEntryRow`])
/// dentro de um [`adw::Clamp`], para caber bem em qualquer largura. O botão
/// "Preparar" só acende com e-mail e senha preenchidos.
pub fn login(acoes: AcoesLogin) -> gtk::Widget {
    // Formulário: e-mail + senha num cartão boxed-list.
    let grupo = adw::PreferencesGroup::new();
    let linha_email = adw::EntryRow::builder().title("E-mail").build();
    linha_email.set_property("input-purpose", gtk::InputPurpose::Email);
    let linha_senha = adw::PasswordEntryRow::builder().title("Senha").build();
    grupo.add(&linha_email);
    grupo.add(&linha_senha);

    // Botão "Preparar" — pílula sugerida, apagada até os dois campos terem texto.
    let botao = gtk::Button::builder()
        .label("Preparar instalação")
        .halign(gtk::Align::Center)
        .css_classes(["pill", "suggested-action"])
        .sensitive(false)
        .build();

    let coluna = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .build();
    coluna.append(&grupo);
    coluna.append(&botao);

    let clamp = adw::Clamp::builder().maximum_size(400).child(&coluna).build();

    let status = adw::StatusPage::builder()
        .icon_name("dialog-password-symbolic")
        .title("Bem-vindo ao RemoteID")
        .description(
            "Prepare esta instalação uma vez para assinar com o seu certificado em \
             nuvem. As credenciais vão só ao RemoteID; a senha não é guardada.",
        )
        .child(&clamp)
        .build();

    // "Preparar" só acende com os dois campos preenchidos.
    let atualizar = {
        let botao = botao.clone();
        let linha_email = linha_email.clone();
        let linha_senha = linha_senha.clone();
        move || {
            let ok = !linha_email.text().trim().is_empty() && !linha_senha.text().is_empty();
            botao.set_sensitive(ok);
        }
    };
    atualizar();
    {
        let f = atualizar.clone();
        linha_email.connect_changed(move |_| f());
    }
    {
        let f = atualizar.clone();
        linha_senha.connect_changed(move |_| f());
    }

    {
        let linha_email = linha_email.clone();
        let linha_senha = linha_senha.clone();
        let preparar = acoes.preparar.clone();
        botao.connect_clicked(move |_| {
            preparar(linha_email.text().trim().to_string(), linha_senha.text().to_string());
        });
    }

    // Rola em janelas baixas, sem esticar horizontalmente.
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&status)
        .build()
        .upcast()
}

// ---------------------------------------------------------------------------
// Tela: seleção de token (quando a carteira tem mais de um certificado)
// ---------------------------------------------------------------------------

/// Ações da tela de seleção de token.
pub struct AcoesSelecao {
    /// Chamada com o `key_name` do certificado escolhido.
    pub escolher: Rc<dyn Fn(String)>,
}

/// Lista os certificados da carteira para o usuário escolher o padrão de
/// assinatura. Cada certificado é uma [`adw::ActionRow`] ativável; o ativo
/// (`ativo`, o `key_name` escolhido) leva um visto. Clicar numa linha escolhe.
///
/// libadwaita: um [`adw::PreferencesGroup`] num [`adw::Clamp`]. Só aparece
/// quando a carteira tem mais de um certificado (com um só, a janela pula).
pub fn selecao_token(
    certificados: &[Certificado],
    ativo: Option<&str>,
    acoes: AcoesSelecao,
) -> gtk::Widget {
    let grupo = adw::PreferencesGroup::builder()
        .title("Escolha o certificado")
        .description(
            "Sua carteira tem mais de um certificado. Escolha qual usar para assinar; \
             dá para trocar depois.",
        )
        .build();

    for cert in certificados {
        let linha = adw::ActionRow::builder()
            .title(&cert.titular)
            .subtitle(format!("{} · série {}", cert.emissor, cert.serial))
            .activatable(true)
            .build();
        // Visto no certificado ativo; seta discreta nos demais.
        if ativo == Some(cert.key_name.as_str()) {
            let visto = gtk::Image::from_icon_name("object-select-symbolic");
            visto.add_css_class("accent");
            linha.add_suffix(&visto);
        } else {
            linha.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        }
        {
            let escolher = acoes.escolher.clone();
            let key = cert.key_name.clone();
            linha.connect_activated(move |_| escolher(key.clone()));
        }
        grupo.add(&linha);
    }

    let clamp = adw::Clamp::builder()
        .maximum_size(520)
        .margin_top(22)
        .margin_bottom(22)
        .margin_start(12)
        .margin_end(12)
        .child(&grupo)
        .build();

    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build()
        .upcast()
}

// ---------------------------------------------------------------------------
// Tela inicial (painel de status)
// ---------------------------------------------------------------------------

/// Ações do painel principal.
pub struct AcoesInicial {
    /// "Reautorizar próxima assinatura" (reset leve, sem confirmação).
    pub reautorizar: Rc<dyn Fn()>,
    /// Abrir a aba de configurações.
    pub abrir_config: Rc<dyn Fn()>,
    /// Abrir a tela de seleção de certificado. Só é oferecida quando a carteira
    /// tem mais de um.
    pub trocar_cert: Rc<dyn Fn()>,
}

/// O painel principal: estado da instalação, certificados, sessões em cache, e
/// o botão "Reautorizar próxima assinatura".
pub fn inicial(estado: &EstadoApp, acoes: AcoesInicial) -> gtk::Widget {
    let raiz = comum::pagina("RemoteID", None);

    // Cabeçalho de estado.
    let estado_lbl = if estado.preparado {
        gtk::Label::builder()
            .label("● Pronto para assinar")
            .halign(gtk::Align::Start)
            .css_classes(["success", "heading"])
            .build()
    } else {
        gtk::Label::builder()
            .label("● Instalação não preparada")
            .halign(gtk::Align::Start)
            .css_classes(["warning", "heading"])
            .build()
    };
    raiz.append(&estado_lbl);

    // Cartão de identidade.
    let card = comum::cartao();
    card.append(&comum::linha("Titular", estado.titular.as_deref().unwrap_or("—")));
    card.append(&comum::linha("Código do desktop", estado.codigo_desktop.as_deref().unwrap_or("—")));
    card.append(&comum::linha(
        "Certificados",
        &format!("{} na carteira", estado.certificados.len()),
    ));
    raiz.append(&card);

    // Certificados.
    // O certificado que o motor vai usar: o escolhido (se ainda na carteira),
    // senão o primeiro. Só marcamos quando há mais de um, que é quando importa.
    let multi = estado.certificados.len() > 1;
    let ativo_key = estado
        .certificado_ativo
        .clone()
        .filter(|k| estado.certificados.iter().any(|c| &c.key_name == k))
        .or_else(|| estado.certificados.first().map(|c| c.key_name.clone()));

    if !estado.certificados.is_empty() {
        raiz.append(
            &gtk::Label::builder().label("Certificados").halign(gtk::Align::Start).css_classes(["heading"]).build(),
        );
        for cert in &estado.certificados {
            let c = comum::cartao();
            c.append(&comum::linha("Titular", &cert.titular));
            c.append(&comum::linha("Emissor", &cert.emissor));
            c.append(&comum::linha("Série", &cert.serial));
            if multi && ativo_key.as_deref() == Some(cert.key_name.as_str()) {
                c.append(&comum::linha("Padrão", "✓ assina com este"));
            }
            raiz.append(&c);
        }
    }

    // Sessões em cache.
    raiz.append(
        &gtk::Label::builder().label("Sessões em cache").halign(gtk::Align::Start).css_classes(["heading"]).build(),
    );
    if estado.sessoes.is_empty() {
        raiz.append(
            &gtk::Label::builder()
                .label("Nenhuma sessão ativa. A próxima assinatura vai pedir PIN e OTP.")
                .halign(gtk::Align::Start)
                .css_classes(["dim-label"])
                .wrap(true)
                .xalign(0.0)
                .build(),
        );
    } else {
        for s in &estado.sessoes {
            let c = comum::cartao();
            c.append(&comum::linha("Certificado", &s.cert_key));
            let emitido = match s.emitido_em {
                Some(e) => format!("epoch {e}"),
                None => "sem data de emissão declarada".to_string(),
            };
            c.append(&comum::linha("Emitido", &emitido));
            c.append(&comum::linha("Visto por último", &format!("epoch {}", s.visto_em)));
            raiz.append(&c);
        }
    }

    // Barra de ações.
    let barra = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8).margin_top(10).build();
    let btn_reaut = gtk::Button::with_label("Reautorizar próxima assinatura");
    btn_reaut.set_tooltip_text(Some(
        "Invalida a sessão em cache. A próxima assinatura vai pedir PIN e OTP de novo.",
    ));
    let espaco = gtk::Box::builder().hexpand(true).build();
    let btn_config = gtk::Button::from_icon_name("emblem-system-symbolic");
    btn_config.set_tooltip_text(Some("Configurações"));
    barra.append(&btn_reaut);
    // "Trocar certificado" só quando a carteira tem mais de um.
    let btn_trocar = if multi {
        let b = gtk::Button::with_label("Trocar certificado");
        b.set_tooltip_text(Some("Escolher qual certificado da carteira assina por padrão."));
        barra.append(&b);
        Some(b)
    } else {
        None
    };
    barra.append(&espaco);
    barra.append(&btn_config);
    raiz.append(&barra);

    {
        let reautorizar = acoes.reautorizar.clone();
        btn_reaut.connect_clicked(move |_| reautorizar());
    }
    {
        let abrir_config = acoes.abrir_config.clone();
        btn_config.connect_clicked(move |_| abrir_config());
    }
    if let Some(b) = btn_trocar {
        let trocar_cert = acoes.trocar_cert.clone();
        b.connect_clicked(move |_| trocar_cert());
    }

    // Rola, que a lista de certificados/sessões pode crescer.
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&raiz)
        .build();
    scroll.upcast()
}

// ---------------------------------------------------------------------------
// Tela de configurações
// ---------------------------------------------------------------------------

/// Ações da aba de configurações.
pub struct AcoesConfig {
    /// Chamada quando o usuário CONFIRMA a reinstalação (o diálogo vermelho já
    /// foi aceito). Reset pesado: apaga o `state.json`.
    pub reinstalar: Rc<dyn Fn()>,
    /// Salva a configuração editada (persistência é da janela).
    pub salvar: Rc<dyn Fn(ConfigApp)>,
    /// Abre a pasta do log no gerenciador de arquivos.
    pub abrir_pasta_log: Rc<dyn Fn()>,
    /// Volta ao painel principal.
    pub voltar: Rc<dyn Fn()>,
}

/// A aba de configurações. Conteúdo mínimo da decisão de 03/09/2026
/// ([[remoteid-app-gtk-decisoes-tomadas]]): duração do cache do PIN, TTL do
/// sessionToken, `nomeAplicacaoDesktop`, caminho do log e o botão Reinstalar
/// (vermelho, com confirmação).
pub fn configuracoes(cfg: &ConfigApp, acoes: AcoesConfig) -> gtk::Widget {
    let raiz = comum::pagina("Configurações", None);

    let grade = gtk::Grid::builder().row_spacing(12).column_spacing(12).build();

    // Cache do PIN (0–60, 0 desliga).
    let rot_cache = gtk::Label::builder().label("Cache do PIN (min)").halign(gtk::Align::End).build();
    let spin_cache = gtk::SpinButton::with_range(0.0, 60.0, 1.0);
    spin_cache.set_value(cfg.cache_pin_min as f64);
    spin_cache.set_tooltip_text(Some("0 desliga o cache: todo pedido de assinatura pede o PIN."));

    // TTL do sessionToken.
    let rot_ttl = gtk::Label::builder().label("TTL da sessão (min)").halign(gtk::Align::End).build();
    let spin_ttl = gtk::SpinButton::with_range(1.0, 360.0, 1.0);
    spin_ttl.set_value(cfg.ttl_sessao_min as f64);
    spin_ttl.set_tooltip_text(Some("Pré-filtro do cache do sessionToken (valor medido ainda pendente)."));

    // nomeAplicacaoDesktop.
    let rot_nome = gtk::Label::builder().label("Nome do aplicativo").halign(gtk::Align::End).build();
    let campo_nome = gtk::Entry::builder().text(&cfg.nome_aplicacao).hexpand(true).build();

    // Caminho do log (só leitura + abrir).
    let rot_log = gtk::Label::builder().label("Pasta do log").halign(gtk::Align::End).build();
    let log_box = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8).hexpand(true).build();
    let campo_log = gtk::Entry::builder().text(&cfg.caminho_log).editable(false).hexpand(true).build();
    let btn_abrir = gtk::Button::with_label("Abrir");
    log_box.append(&campo_log);
    log_box.append(&btn_abrir);

    grade.attach(&rot_cache, 0, 0, 1, 1);
    grade.attach(&spin_cache, 1, 0, 1, 1);
    grade.attach(&rot_ttl, 0, 1, 1, 1);
    grade.attach(&spin_ttl, 1, 1, 1, 1);
    grade.attach(&rot_nome, 0, 2, 1, 1);
    grade.attach(&campo_nome, 1, 2, 1, 1);
    grade.attach(&rot_log, 0, 3, 1, 1);
    grade.attach(&log_box, 1, 3, 1, 1);
    raiz.append(&grade);

    // Barra: voltar / salvar.
    let barra = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8).margin_top(6).build();
    let btn_voltar = gtk::Button::with_label("Voltar");
    let espaco = gtk::Box::builder().hexpand(true).build();
    let btn_salvar = gtk::Button::with_label("Salvar");
    btn_salvar.add_css_class("suggested-action");
    barra.append(&btn_voltar);
    barra.append(&espaco);
    barra.append(&btn_salvar);
    raiz.append(&barra);

    // Zona de perigo: Reinstalar.
    let sep = gtk::Separator::new(gtk::Orientation::Horizontal);
    sep.set_margin_top(10);
    raiz.append(&sep);
    raiz.append(
        &gtk::Label::builder().label("Zona de perigo").halign(gtk::Align::Start).css_classes(["heading", "error"]).build(),
    );
    let perigo = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(12).build();
    let aviso = gtk::Label::builder()
        .label("Reinstalar apaga o estado local (state.json e a chave desta instalação) e exige novo login, registro e carteira. O log de diagnóstico é preservado.")
        .wrap(true)
        .xalign(0.0)
        .hexpand(true)
        .css_classes(["dim-label"])
        .build();
    let btn_reinstalar = gtk::Button::with_label("Reinstalar");
    btn_reinstalar.add_css_class("destructive-action");
    btn_reinstalar.set_valign(gtk::Align::Center);
    perigo.append(&aviso);
    perigo.append(&btn_reinstalar);
    raiz.append(&perigo);

    // Fios.
    {
        let voltar = acoes.voltar.clone();
        btn_voltar.connect_clicked(move |_| voltar());
    }
    {
        let abrir = acoes.abrir_pasta_log.clone();
        btn_abrir.connect_clicked(move |_| abrir());
    }
    {
        let salvar = acoes.salvar.clone();
        let spin_cache = spin_cache.clone();
        let spin_ttl = spin_ttl.clone();
        let campo_nome = campo_nome.clone();
        let caminho_log = cfg.caminho_log.clone();
        btn_salvar.connect_clicked(move |_| {
            salvar(ConfigApp {
                cache_pin_min: spin_cache.value_as_int().max(0) as u32,
                ttl_sessao_min: spin_ttl.value_as_int().max(1) as u32,
                nome_aplicacao: campo_nome.text().to_string(),
                caminho_log: caminho_log.clone(),
            });
        });
    }
    {
        // Confirmação vermelha antes de reinstalar de fato.
        let reinstalar = acoes.reinstalar.clone();
        btn_reinstalar.connect_clicked(move |botao| {
            let reinstalar = reinstalar.clone();
            confirmar_reinstalar(botao, reinstalar);
        });
    }

    raiz.upcast()
}

/// Diálogo modal de confirmação da reinstalação. Usa a janela do widget como
/// pai (transiente) e o loop da aplicação já em curso — sem loop aninhado,
/// porque a janela principal já roda um. A ação só dispara no "Reinstalar".
fn confirmar_reinstalar(origem: &gtk::Button, reinstalar: Rc<dyn Fn()>) {
    let pai = origem.root().and_downcast::<gtk::Window>();
    let dialogo = gtk::Window::builder()
        .title("Reinstalar?")
        .modal(true)
        .resizable(false)
        .default_width(380)
        .build();
    if let Some(p) = &pai {
        dialogo.set_transient_for(Some(p));
    }

    let caixa = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(14)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    caixa.append(
        &gtk::Label::builder()
            .label("Isto apaga o estado local e a chave desta instalação. Você vai precisar preparar tudo de novo (login, registro e carteira). O log de diagnóstico é mantido.")
            .wrap(true)
            .xalign(0.0)
            .build(),
    );
    let barra = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8).halign(gtk::Align::End).build();
    let cancelar = gtk::Button::with_label("Cancelar");
    let confirmar = gtk::Button::with_label("Reinstalar");
    confirmar.add_css_class("destructive-action");
    barra.append(&cancelar);
    barra.append(&confirmar);
    caixa.append(&barra);
    dialogo.set_child(Some(&caixa));

    {
        let dialogo = dialogo.clone();
        cancelar.connect_clicked(move |_| dialogo.close());
    }
    {
        let dialogo = dialogo.clone();
        confirmar.connect_clicked(move |_| {
            reinstalar();
            dialogo.close();
        });
    }
    dialogo.present();
}

// ---------------------------------------------------------------------------
// Tela de PIN/OTP — a MESMA que o daemon mostra antes de assinar
// ---------------------------------------------------------------------------

/// O diálogo de PIN/OTP, compartilhado entre a janela (preview) e o daemon.
///
/// O daemon chama [`pin_otp::rodar_modal`] (que embrulha o conteúdo numa
/// janela modal com um `glib::MainLoop` aninhado, porque o daemon não tem
/// loop de aplicação); o `--preview` embute [`pin_otp::montar`] direto numa
/// página da galeria. As DUAS usam o mesmo `montar`, então o que você valida
/// visualmente é exatamente o que o testador vai ver ao assinar.
pub mod pin_otp {
    use std::cell::RefCell;
    use std::rc::Rc;

    use gtk::glib;
    use gtk::prelude::*;

    /// Os widgets do diálogo, já montados e com a regra de sensibilidade do
    /// botão "Assinar" ligada. Devolvidos para o chamador decidir o que os
    /// botões fazem (fechar loop aninhado, no daemon; nada, no preview).
    pub struct DialogoPinOtp {
        pub raiz: gtk::Box,
        pub campo_pin: gtk::PasswordEntry,
        pub campo_otp: gtk::Entry,
        pub botao_ok: gtk::Button,
        pub botao_cancelar: gtk::Button,
    }

    /// Monta o conteúdo do diálogo. `titular` vira o cabeçalho "Assinar como
    /// ...", `hospedeiro` a legenda "Solicitado por ...", `pin_inicial`
    /// pré-preenche o PIN (cache ainda válido). O botão "Assinar" só ativa com
    /// PIN E OTP preenchidos: o `tokensessao` exige os dois juntos.
    pub fn montar(
        titular: Option<&str>,
        hospedeiro: Option<&str>,
        pin_inicial: Option<&str>,
    ) -> DialogoPinOtp {
        let raiz = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(12)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(18)
            .margin_end(18)
            .build();

        let cabecalho = match titular {
            Some(nome) if !nome.is_empty() => format!("Assinar como {nome}"),
            _ => "Autorizar assinatura".to_string(),
        };
        raiz.append(
            &gtk::Label::builder().label(&cabecalho).halign(gtk::Align::Start).css_classes(["title-3"]).build(),
        );

        if let Some(host) = hospedeiro {
            if !host.is_empty() {
                raiz.append(
                    &gtk::Label::builder()
                        .label(format!("Solicitado por {host}"))
                        .halign(gtk::Align::Start)
                        .css_classes(["dim-label"])
                        .build(),
                );
            }
        }

        let grade = gtk::Grid::builder().row_spacing(8).column_spacing(10).build();
        let rot_pin = gtk::Label::builder().label("PIN").halign(gtk::Align::End).build();
        let campo_pin = gtk::PasswordEntry::builder()
            .show_peek_icon(true)
            .hexpand(true)
            .activates_default(true)
            .build();
        if let Some(p) = pin_inicial {
            campo_pin.set_text(p);
        }
        let rot_otp = gtk::Label::builder().label("OTP").halign(gtk::Align::End).build();
        let campo_otp = gtk::Entry::builder()
            .visibility(false)
            .input_purpose(gtk::InputPurpose::Digits)
            .hexpand(true)
            .activates_default(true)
            .build();

        grade.attach(&rot_pin, 0, 0, 1, 1);
        grade.attach(&campo_pin, 1, 0, 1, 1);
        grade.attach(&rot_otp, 0, 1, 1, 1);
        grade.attach(&campo_otp, 1, 1, 1, 1);
        raiz.append(&grade);

        let botoes = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk::Align::End)
            .build();
        let botao_cancelar = gtk::Button::with_label("Cancelar");
        let botao_ok = gtk::Button::with_label("Assinar");
        botao_ok.add_css_class("suggested-action");
        botoes.append(&botao_cancelar);
        botoes.append(&botao_ok);
        raiz.append(&botoes);

        // "Assinar" só com os dois campos preenchidos.
        let atualizar_ok = {
            let botao_ok = botao_ok.clone();
            let campo_pin = campo_pin.clone();
            let campo_otp = campo_otp.clone();
            move || {
                let ok = !campo_pin.text().is_empty() && !campo_otp.text().is_empty();
                botao_ok.set_sensitive(ok);
            }
        };
        atualizar_ok();
        {
            let f = atualizar_ok.clone();
            campo_pin.connect_changed(move |_| f());
        }
        {
            let f = atualizar_ok.clone();
            campo_otp.connect_changed(move |_| f());
        }

        DialogoPinOtp { raiz, campo_pin, campo_otp, botao_ok, botao_cancelar }
    }

    /// Roda o diálogo como uma janela modal bloqueante, do jeito que o daemon
    /// precisa (sem loop de aplicação). Devolve `Some((pin, otp))` se o
    /// usuário confirmar, `None` se cancelar ou fechar. Chama `gtk::init()`
    /// (idempotente, na thread do chamador).
    pub fn rodar_modal(
        titular: Option<&str>,
        hospedeiro: Option<&str>,
        pin_inicial: Option<&str>,
    ) -> Result<Option<(String, String)>, String> {
        if let Err(e) = gtk::init() {
            return Err(format!("GTK não inicializou (sem display gráfico?): {e}"));
        }

        let d = montar(titular, hospedeiro, pin_inicial);
        let resultado: Rc<RefCell<Option<(String, String)>>> = Rc::new(RefCell::new(None));
        let loop_local = glib::MainLoop::new(None, false);

        let janela = gtk::Window::builder()
            .title("RemoteID — autorizar assinatura")
            .modal(true)
            .resizable(false)
            .default_width(360)
            .child(&d.raiz)
            .build();
        janela.set_default_widget(Some(&d.botao_ok));

        // Transiente à janela principal do app, quando existe: assim o diálogo
        // é modal SOBRE ela e bloqueia cliques na janela enquanto a assinatura
        // está em curso. Isso evita reentrância no `Servico` (a UI não dispara
        // Status/Reautorizar no meio de um Sign). No daemon standalone antigo
        // não havia janela pai; aqui o app unificado fornece uma.
        if let Some(app) = gtk::gio::Application::default().and_downcast::<gtk::Application>() {
            if let Some(w) = app.active_window() {
                janela.set_transient_for(Some(&w));
            }
        }

        {
            let resultado = resultado.clone();
            let loop_local = loop_local.clone();
            let campo_pin = d.campo_pin.clone();
            let campo_otp = d.campo_otp.clone();
            d.botao_ok.connect_clicked(move |_| {
                *resultado.borrow_mut() =
                    Some((campo_pin.text().to_string(), campo_otp.text().to_string()));
                loop_local.quit();
            });
        }
        {
            let loop_local = loop_local.clone();
            d.botao_cancelar.connect_clicked(move |_| loop_local.quit());
        }
        {
            let loop_local = loop_local.clone();
            janela.connect_close_request(move |_| {
                loop_local.quit();
                glib::Propagation::Proceed
            });
        }

        janela.present();
        loop_local.run();
        janela.close();

        // Drena eventos pendentes para a janela sumir antes de devolver.
        let ctx = glib::MainContext::default();
        while ctx.iteration(false) {}

        let saida = resultado.borrow_mut().take();
        Ok(saida)
    }
}
