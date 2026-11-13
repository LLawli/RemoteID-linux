#!/usr/bin/env bash
# Todos os gates do projeto, na ordem do mais barato para o mais caro. A CI
# roda este mesmo script: verde aqui é verde lá.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
# Sem a janela, nada pode depender de GTK: a linha de comando e o `servir`
# inteiros compilam e passam nos testes.
cargo clippy --all-targets --locked --no-default-features -- -D warnings
cargo test --locked --no-default-features
cargo audit

appstreamcli validate --no-net --explain dev.lukakuuhaku.Ancora.Driver.RemoteID.metainfo.xml
