//! O ref e os caminhos da extensão aparecem em arquivos que o compilador não
//! vê. Um nome trocado num deles só aparece depois de instalado, como
//! extensão que o Âncora não acha ou módulo que o p11-kit não carrega.

use remoteid::APP_ID;

const MANIFESTO: &str = include_str!("../dev.lukakuuhaku.Ancora.Driver.RemoteID.yml");
const METAINFO: &str = include_str!("../dev.lukakuuhaku.Ancora.Driver.RemoteID.metainfo.xml");
const DESCRITOR: &str = include_str!("../ancora.toml");

#[test]
fn o_ref_e_o_mesmo_no_manifesto_e_no_metainfo() {
    assert!(MANIFESTO.contains(&format!("\nid: {APP_ID}\n")));
    assert!(METAINFO.contains(&format!("<id>{APP_ID}</id>")));
    assert!(METAINFO.contains("<extends>dev.lukakuuhaku.Ancora</extends>"));
}

#[test]
fn o_descritor_aponta_para_o_que_o_manifesto_instala() {
    for (campo, caminho, origem) in [
        (
            "modulo",
            "lib/libremoteid.so",
            "target/release/libremoteid.so",
        ),
        ("executavel", "bin/remoteid", "target/release/remoteid"),
    ] {
        assert!(
            DESCRITOR.contains(&format!("{campo} = \"{caminho}\"")),
            "o ancora.toml não tem {campo} = {caminho}"
        );
        let (diretorio, _) = caminho.rsplit_once('/').unwrap();
        assert!(
            MANIFESTO.contains(&format!("{origem} -t ${{FLATPAK_DEST}}/{diretorio}\n")),
            "o manifesto não instala {origem} em {diretorio}"
        );
    }
}
