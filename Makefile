# RemoteID-linux — atalhos de desenvolvimento.

.PHONY: preview app teste-local build release test clippy check help

help:
	@echo "Alvos:"
	@echo "  make preview      abre a galeria de telas GTK com dados FICTÍCIOS (sem motor, sem socket)"
	@echo "  make app          roda o app unificado (janela + servidor do socket no mesmo processo)"
	@echo "  make teste-local  sobe o servidor RemoteID FALSO + conta de teste em /tmp"
	@echo "  make build        compila o workspace (debug)"
	@echo "  make release      compila o workspace (release)"
	@echo "  make test         cargo test"
	@echo "  make clippy       cargo clippy --all-targets"
	@echo "  make check        porta de validação: test + clippy + build --release"

# Validação visual das telas, sem motor nem socket: cada tela em janela simultânea com mocks.
preview:
	cargo run -q -p remoteid-gtk --bin remoteid-app -- --preview

# O app unificado: janela + servidor do socket no mesmo processo.
app:
	cargo run -q -p remoteid-gtk --bin remoteid-app

# Ambiente de teste ponta a ponta: servidor RemoteID falso + conta isolada em
# /tmp, com certificado e OTP/PIN sintéticos. Nada toca a conta real.
teste-local:
	tools/teste-local.sh

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clippy:
	cargo clippy --all-targets

# A porta de validação do projeto (CLAUDE.md).
check:
	cargo test && cargo clippy --all-targets && cargo build --release
