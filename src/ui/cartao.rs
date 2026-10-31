//! O cartão de um certificado: o grande, da carteira, com o selo da sessão, e
//! o pequeno, que lembra qual certificado está em jogo (detalhes, diálogo de
//! PIN e OTP).

use adw::prelude::*;
use gtk::glib;
use remoteid::carteira::{Cartao, Documento, Sessao};

use super::estilo::CORES;

pub fn texto(rotulo: &str, classes: &[&str]) -> gtk::Label {
    gtk::Label::builder()
        .label(rotulo)
        .xalign(0.0)
        .css_classes(classes.iter().map(|c| c.to_string()).collect::<Vec<_>>())
        .build()
}

/// Um instante no fuso desta máquina, pelo `formato` do `strftime`.
pub fn data(segundos: u64, formato: &str) -> String {
    i64::try_from(segundos)
        .ok()
        .and_then(|s| glib::DateTime::from_unix_local(s).ok())
        .and_then(|d| d.format(formato).ok())
        .map(String::from)
        .unwrap_or_default()
}

/// `e-CPF em nuvem`, `e-CNPJ em nuvem`, ou só `Em nuvem`.
pub fn tipo(documento: Option<&Documento>) -> String {
    match documento {
        Some(d) => format!("{} em nuvem", d.tipo()),
        None => "Em nuvem".into(),
    }
}

/// O aviso de validade: quantos dias faltam, ou que já venceu.
pub fn alerta(dias: Option<i64>) -> Option<gtk::Box> {
    let dias = dias?;
    let caixa = gtk::Box::builder()
        .spacing(5)
        .valign(gtk::Align::Center)
        .css_classes(["alerta"])
        .build();
    let rotulo = match dias {
        ..0 => {
            caixa.add_css_class("vencido");
            "Vencido".to_string()
        }
        0 => "Vence hoje".to_string(),
        1 => "1 dia".to_string(),
        n => format!("{n} dias"),
    };
    caixa.append(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
    caixa.append(&gtk::Label::new(Some(&rotulo)));
    Some(caixa)
}

fn icone() -> gtk::Image {
    gtk::Image::from_icon_name("application-certificate-symbolic")
}

fn classe_cor(cor: usize) -> String {
    format!("cartao-{}", cor % CORES)
}

/// O cartão pequeno: ícone, nome e tipo.
pub fn mini(nome: &str, tipo: &str, cor: usize, dias: Option<i64>) -> gtk::Box {
    let raiz = gtk::Box::builder()
        .spacing(12)
        .css_classes(["cartao", "mini", classe_cor(cor).as_str()])
        .build();
    raiz.append(&icone());
    let meio = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    let n = texto(nome, &["cartao-nome"]);
    n.set_ellipsize(gtk::pango::EllipsizeMode::End);
    meio.append(&n);
    meio.append(&texto(tipo, &["cartao-tipo"]));
    raiz.append(&meio);
    if let Some(a) = alerta(dias) {
        raiz.append(&a);
    }
    raiz
}

/// O cartão grande da carteira. O selo só aparece no cartão que assina.
pub struct Grande {
    pub raiz: gtk::Box,
    selo: gtk::Button,
    selo_icone: gtk::Image,
    selo_texto: gtk::Label,
}

impl Grande {
    pub fn novo(c: &Cartao, cor: usize, agora: u64) -> Grande {
        let raiz = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .width_request(340)
            .height_request(214)
            .halign(gtk::Align::Center)
            .css_classes(["cartao", classe_cor(cor).as_str()])
            .build();

        let topo = gtk::Box::builder().spacing(8).build();
        topo.append(&icone());
        let t = texto(&tipo(c.documento.as_ref()), &["cartao-tipo"]);
        t.set_hexpand(true);
        topo.append(&t);
        if let Some(a) = alerta(c.alerta(agora)) {
            topo.append(&a);
        }
        raiz.append(&topo);

        raiz.append(&gtk::Box::builder().vexpand(true).build());
        let n = texto(&c.nome, &["cartao-nome"]);
        n.set_wrap(true);
        n.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        raiz.append(&n);
        if let Some(d) = &c.documento {
            raiz.append(&texto(&d.formatado(), &["cartao-doc"]));
        }

        let fundo = gtk::Box::builder().spacing(8).margin_top(12).build();
        let validade = gtk::Box::builder()
            .spacing(6)
            .valign(gtk::Align::Center)
            .hexpand(true)
            .tooltip_text("Validade")
            .build();
        if let Some(v) = c.validade {
            validade.append(&gtk::Image::from_icon_name("x-office-calendar-symbolic"));
            validade.append(&texto(&data(v, "%d/%m/%Y"), &["cartao-data"]));
        }
        fundo.append(&validade);

        let selo_icone = gtk::Image::builder().pixel_size(28).build();
        let selo_texto = gtk::Label::new(None);
        let interno = gtk::Box::builder().spacing(8).build();
        interno.append(&selo_icone);
        interno.append(&selo_texto);
        let selo = gtk::Button::builder()
            .child(&interno)
            .action_name("win.reautorizar")
            .valign(gtk::Align::Center)
            .css_classes(["selo"])
            .build();
        fundo.append(&selo);
        raiz.append(&fundo);

        let grande = Grande {
            raiz,
            selo,
            selo_icone,
            selo_texto,
        };
        grande.mostrar_sessao(c);
        grande
    }

    /// O selo: cadeado aberto com a hora em que a sessão vence, ou fechado
    /// quando a próxima assinatura pede PIN e OTP.
    pub fn mostrar_sessao(&self, c: &Cartao) {
        self.selo.set_visible(c.ativo);
        match c.sessao {
            Sessao::Aberta { ate } => {
                self.selo_icone
                    .set_icon_name(Some("changes-allow-symbolic"));
                self.selo_texto.set_label(&match ate {
                    Some(ate) => format!("até {}", data(ate, "%H:%M")),
                    None => "Aberta".into(),
                });
                self.selo.remove_css_class("fechado");
                self.selo.add_css_class("aberto");
                self.selo.set_tooltip_text(Some("Reautorizar"));
            }
            Sessao::Fechada => {
                self.selo_icone
                    .set_icon_name(Some("changes-prevent-symbolic"));
                self.selo_texto.set_label("PIN e OTP");
                self.selo.remove_css_class("aberto");
                self.selo.add_css_class("fechado");
                self.selo.set_tooltip_text(None);
            }
        }
    }
}
