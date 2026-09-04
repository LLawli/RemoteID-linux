#!/usr/bin/env bash
# Ambiente de TESTE local do DesktopID, ponta a ponta, sem tocar na conta real.
#
# Sobe um servidor RemoteID FALSO (remoteid-mock) e prepara uma conta de teste
# isolada em /tmp/remoteid-teste (certificado e chave SINTÉTICOS). Deixe este
# terminal aberto: o servidor falso roda aqui, e Ctrl+C encerra tudo.
#
# Credenciais fixas de teste:
#   login  teste@remoteid.local / teste-1234
#   PIN    1234        OTP 123456
#
# Uso: tools/teste-local.sh [porta]   (padrão 8799)
set -euo pipefail

PORTA="${1:-8799}"
URL="http://localhost:${PORTA}"
DIR="/tmp/remoteid-teste"
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$RAIZ"

echo "→ compilando (mock, cli, app)…"
cargo build -q -p remoteid-mock -p remoteid-cli -p remoteid-gtk

rm -rf "$DIR"

echo "→ subindo o servidor RemoteID FALSO em ${URL}"
target/debug/remoteid-mock "$PORTA" &
MOCK=$!
trap 'kill "$MOCK" 2>/dev/null || true; echo; echo "servidor de teste encerrado."; exit 0' INT TERM
sleep 0.6

echo "→ preparando a conta de TESTE (login + registro + carteira) em ${DIR}"
TEST_URL="$URL" \
REMOTEID_EMAIL=teste@remoteid.local REMOTEID_SENHA=teste-1234 \
  target/debug/remoteid preparar

cat <<EOF

============================================================
 Ambiente de teste PRONTO — tudo em ${DIR}, conta real intacta.
 Deixe ESTE terminal aberto (o servidor falso roda aqui; Ctrl+C encerra).

 O interruptor é UM só: TEST_URL. Com ele, app, CLI e módulo PKCS#11 relocam
 juntos para /tmp e falam com o mock. Sem ele, tudo usa os caminhos de produção
 (e aí basta o módulo estar registrado no p11-kit — nada de variáveis).

 1. Abra o app (janela GTK + servidor do socket para o módulo PKCS#11):

      TEST_URL=${URL} ${RAIZ}/target/debug/remoteid-app

 2. Assine pelo Papers ou pela CLI em OUTRO terminal:

      TEST_URL=${URL} ${RAIZ}/target/debug/remoteid assinar --arquivo algum.pdf
    (pede PIN 1234 / OTP 123456; a assinatura vai pelo motor → mock e confere
     com o certificado falso)

 Credenciais: login teste@remoteid.local / teste-1234
              PIN 1234   OTP 123456
============================================================
EOF

wait "$MOCK"
