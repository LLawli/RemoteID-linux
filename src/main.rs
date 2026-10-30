use adw::prelude::*;
use remoteid::{APP_ID, NOME};

fn main() -> gtk::glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(montar_janela);
    app.run()
}

fn montar_janela(app: &adw::Application) {
    let pagina = adw::StatusPage::builder().title(NOME).build();

    let conteudo = adw::ToolbarView::new();
    conteudo.add_top_bar(&adw::HeaderBar::new());
    conteudo.set_content(Some(&pagina));

    adw::ApplicationWindow::builder()
        .application(app)
        .title(NOME)
        .default_width(560)
        .default_height(600)
        .content(&conteudo)
        .build()
        .present();
}
