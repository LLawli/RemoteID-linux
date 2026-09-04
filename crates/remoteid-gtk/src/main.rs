//! Ponto de entrada do executável `remoteid-app`.
//!
//! Inicializa a `adw::Application` para habilitar os estilos e temas do Libadwaita
//! e direciona o fluxo para o modo normal ou para o modo `--preview`.

use adw::prelude::*;
use remoteid_gtk::{app, preview};

const ID_APP: &str = "dev.lukakuuhaku.RemoteID";
const ID_PREVIEW: &str = "dev.lukakuuhaku.RemoteID.Preview";
const ID_TESTE: &str = "dev.lukakuuhaku.RemoteID.Teste";

const AJUDA: &str = "\
remoteid-app — Aplicativo desktop para certificados em nuvem RemoteID (Certisign)

USO:
  remoteid-app [OPÇÕES]

OPÇÕES:
  --preview    Abre todas as telas da interface em paralelo com dados fictícios
  -h, --help   Exibe esta mensagem de ajuda
";

fn main() -> gtk::glib::ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{AJUDA}");
        return gtk::glib::ExitCode::SUCCESS;
    }

    let e_preview = args.iter().any(|a| a == "--preview");
    let e_teste = !e_preview && remoteid_caminhos::em_teste();

    let app_id = if e_preview {
        ID_PREVIEW
    } else if e_teste {
        ID_TESTE
    } else {
        ID_APP
    };

    let aplicacao = adw::Application::builder().application_id(app_id).build();

    if e_preview {
        aplicacao.connect_activate(preview::construir_preview);
    } else {
        aplicacao.connect_activate(app::construir_app);
    }

    // Passamos vetor vazio para o GTK não consumir flags customizadas como --preview
    aplicacao.run_with_args(&Vec::<String>::new())
}
