//! O CSS da carteira: os cartões, o selo da sessão e os avisos de validade.

use gtk::gdk;

const CSS: &str = r#"
.cartao {
  color: white;
  border-radius: 22px;
  padding: 18px 20px;
  box-shadow: 0 14px 28px -8px alpha(black, 0.5), 0 2px 6px alpha(black, 0.3);
}
.cartao-0 {
  background-image: linear-gradient(155deg, alpha(white, 0.18), alpha(white, 0) 48%),
                    linear-gradient(135deg, @blue_3, @blue_5);
}
.cartao-1 {
  background-image: linear-gradient(155deg, alpha(white, 0.18), alpha(white, 0) 48%),
                    linear-gradient(135deg, @purple_3, @purple_5);
}
.cartao-2 {
  background-image: linear-gradient(155deg, alpha(white, 0.18), alpha(white, 0) 48%),
                    linear-gradient(135deg, @brown_3, @brown_5);
}
.cartao-3 {
  background-image: linear-gradient(155deg, alpha(white, 0.18), alpha(white, 0) 48%),
                    linear-gradient(135deg, @dark_1, @dark_3);
}
.cartao.mini {
  border-radius: 16px;
  padding: 10px 14px;
  box-shadow: 0 6px 12px -4px alpha(black, 0.4), 0 1px 3px alpha(black, 0.3);
}
.cartao-tipo { font-weight: 700; font-size: 9pt; opacity: 0.88; }
.cartao-nome { font-weight: 800; font-size: 16pt; }
.mini .cartao-nome { font-size: 11pt; }
.cartao-doc { opacity: 0.82; font-feature-settings: "tnum"; }
.cartao-data { font-weight: 600; opacity: 0.9; font-feature-settings: "tnum"; }
.alerta {
  background: @yellow_3;
  color: #3d2a00;
  border-radius: 999px;
  padding: 2px 10px;
  font-weight: 700;
  font-size: 9pt;
}
.alerta.vencido { background: @red_3; color: white; }
button.selo {
  min-height: 0;
  min-width: 0;
  padding: 6px 18px 6px 12px;
  border-radius: 999px;
  border: none;
  box-shadow: none;
  font-weight: 800;
}
button.selo:disabled { opacity: 1; }
button.selo label { font-size: 13pt; }
button.selo.aberto { background: @green_1; color: #0b3d1f; }
button.selo.aberto:hover { background: shade(@green_1, 1.08); }
button.selo.aberto:active { background: shade(@green_1, 0.92); }
button.selo.fechado { background: alpha(black, 0.3); color: white; }
.marca {
  min-width: 76px;
  min-height: 76px;
  border-radius: 22px;
  color: white;
  background-image: linear-gradient(135deg, @blue_3, @blue_5);
  box-shadow: 0 10px 20px -6px alpha(black, 0.45);
}
.barra-detalhes { padding: 10px 0 12px 0; opacity: 0.8; }
"#;

/// Quantas cores de cartão há; o cartão `i` usa `cartao-{i % CORES}`.
pub const CORES: usize = 4;

pub fn instalar() {
    let provedor = gtk::CssProvider::new();
    provedor.load_from_string(CSS);
    if let Some(tela) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &tela,
            &provedor,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}
