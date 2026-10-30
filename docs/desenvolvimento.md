# Desenvolvimento

## Dependências

- Rust estável (1.92 ou mais novo).
- GTK 4.18 e libadwaita 1.7, ou mais novos, com os cabeçalhos
  (`gtk4-devel libadwaita-devel` no Fedora).
- `appstream`, para validar o metainfo.
- `cargo-audit`.
- Para a extensão: o Âncora (`dev.lukakuuhaku.Ancora`) instalado,
  `org.flatpak.Builder`, `org.gnome.Sdk//51` e
  `org.freedesktop.Sdk.Extension.rust-stable//26.08`.

## Gates

```bash
scripts/ci.sh
```

Formatação, clippy com avisos como erro, testes, `cargo audit` e validação do
metainfo. A CI roda o mesmo script, num contêiner Fedora 44, porque o Ubuntu
dos runners traz GTK e libadwaita mais antigos que os do runtime.

## Dependências Rust e o Flatpak

O `flatpak-builder` constrói sem rede. Cada crate do `Cargo.lock` precisa estar
em `flatpak/cargo-sources.json`, e depois de mexer nas dependências é preciso
regenerar:

```bash
scripts/cargo-sources.py
```

O teste `tests/flatpak.rs` falha enquanto os dois estiverem fora de sincronia.
O script cobre só crates do crates.io; uma dependência git é recusada.

## Paridade com o RemoteID-linux

`tests/paridade.rs` compara o protocolo com fixtures gravadas rodando o
RemoteID-linux v0.3.2, e roda no `scripts/ci.sh` como qualquer teste. Para
regenerar as fixtures, veja [paridade/README.md](../paridade/README.md).

## Construir a extensão

```bash
flatpak run org.flatpak.Builder --user --install --force-clean build-dir flatpak/dev.lukakuuhaku.Ancora.Driver.RemoteID.yml
flatpak run --command=ancora dev.lukakuuhaku.Ancora extensoes
flatpak run --command=/app/extensoes/driver/RemoteID/bin/remoteid dev.lukakuuhaku.Ancora
```

O segundo comando confere que o Âncora leu o `ancora.toml`; o terceiro abre a
janela dentro do sandbox do Âncora, como o atalho fará.
