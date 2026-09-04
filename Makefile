# RemoteID-linux — atalhos de desenvolvimento.

.PHONY: preview app teste-local teste-integracao auditar build release test clippy check help

help:
	@echo "Alvos:"
	@echo "  make preview      abre a galeria de telas GTK com dados FICTÍCIOS (sem motor, sem socket)"
	@echo "  make app          roda o app unificado (janela + servidor do socket no mesmo processo)"
	@echo "  make teste-local  sobe o servidor RemoteID FALSO + conta de teste em /tmp"
	@echo "  make teste-integracao  gate ponta a ponta: pkcs11-tool → módulo → socket → mock"
	@echo "  make auditar      reprova se algum segredo escapou para arquivo versionado"
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

# Gate ponta a ponta do módulo PKCS#11, sem humano no meio. Fora do `check`
# porque depende de ferramenta externa (opensc/openssl) e sobe processos: é um
# gate de CI próprio, não parte da compilação. Exige que NÃO haja um
# `teste-local` no ar (os dois usam /tmp/remoteid-teste).
teste-integracao:
	tools/teste-integracao-pkcs11.sh

# Barreira de publicação: PIN/OTP/token/chave/estado em arquivo versionado.
auditar:
	tools/auditar-segredos.sh

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
