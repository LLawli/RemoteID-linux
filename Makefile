# RemoteID-linux — atalhos de desenvolvimento.

.PHONY: teste-local build release test clippy check help

help:
	@echo "Alvos:"
	@echo "  make teste-local  sobe o servidor RemoteID FALSO + conta de teste em /tmp"
	@echo "  make build        compila o workspace (debug)"
	@echo "  make release      compila o workspace (release)"
	@echo "  make test         cargo test"
	@echo "  make clippy       cargo clippy --all-targets"
	@echo "  make check        porta de validação: test + clippy + build --release"
	@echo ""
	@echo "  (o app GTK — 'make preview'/'make app' — volta quando a crate"
	@echo "   remoteid-gtk for reconstruída; ver docs/gtk-app-spec.md)"

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
