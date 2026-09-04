#!/usr/bin/env sh
# Instala o RemoteID-linux no diretório do usuário. Não pede root e não escreve
# fora de ~/.local (e de ~/.config, para registrar o módulo no p11-kit).
#
# Este script é fonte ÚNICA: o `make instalar` chama ele apontando para
# `target/release`, e o tarball da release o inclui apontando para si mesmo.
# Duas cópias divergiriam no primeiro conserto.
#
# Uso:
#   ./instalar.sh                      # binários ao lado do script (tarball)
#   ./instalar.sh --de target/release  # binários em outro lugar (repositório)
#   PREFIX=/opt/x ./instalar.sh        # outro destino (padrão: ~/.local)
set -eu

AQUI="$(cd "$(dirname "$0")" && pwd)"
DE="$AQUI"
DADOS="$AQUI/data"
[ -d "$DADOS" ] || DADOS="$AQUI"

while [ $# -gt 0 ]; do
    case "$1" in
        --de)    DE="$2"; shift 2 ;;
        --dados) DADOS="$2"; shift 2 ;;
        *) echo "opção desconhecida: $1" >&2; exit 2 ;;
    esac
done

PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
LIB="$PREFIX/lib/remoteid"
APPS="$PREFIX/share/applications"
ICONES="$PREFIX/share/icons/hicolor"
P11="${XDG_CONFIG_HOME:-$HOME/.config}/pkcs11/modules"

falta() { echo "erro: não achei $1" >&2; exit 1; }
[ -f "$DE/remoteid" ]                 || falta "$DE/remoteid"
[ -f "$DE/remoteid-app" ]             || falta "$DE/remoteid-app"
[ -f "$DE/libremoteid_pkcs11.so" ]    || falta "$DE/libremoteid_pkcs11.so"

mkdir -p "$BIN" "$LIB" "$APPS" "$ICONES/scalable/apps" "$ICONES/symbolic/apps" "$P11"

# O app procura o `remoteid` como binário VIZINHO (current_exe().parent()), então
# os dois têm de ficar no mesmo diretório. Separá-los quebra a tela de login.
install -m755 "$DE/remoteid"     "$BIN/remoteid"
install -m755 "$DE/remoteid-app" "$BIN/remoteid-app"
install -m644 "$DE/libremoteid_pkcs11.so" "$LIB/libremoteid_pkcs11.so"

install -m644 "$DADOS/applications/dev.lukakuuhaku.RemoteID.desktop" "$APPS/"
install -m644 "$DADOS/icons/hicolor/scalable/apps/dev.lukakuuhaku.RemoteID.svg" "$ICONES/scalable/apps/"
install -m644 "$DADOS/icons/hicolor/symbolic/apps/dev.lukakuuhaku.RemoteID-symbolic.svg" "$ICONES/symbolic/apps/"

# Registro no p11-kit: é o que faz Papers, Firefox e Chromium enxergarem o
# certificado. Nível de usuário, sem root e sem modutil.
cat > "$P11/remoteid.module" <<EOF
# Gerado por instalar.sh do RemoteID-linux.
module: $LIB/libremoteid_pkcs11.so
EOF

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$ICONES" >/dev/null 2>&1 || true

echo "instalado em $PREFIX"
echo "  binários : $BIN/remoteid, $BIN/remoteid-app"
echo "  módulo   : $LIB/libremoteid_pkcs11.so (registrado em $P11/remoteid.module)"
echo "  lançador : $APPS/dev.lukakuuhaku.RemoteID.desktop"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo; echo "atenção: $BIN não está no seu PATH." ;;
esac
echo
echo "O aplicativo precisa estar ABERTO para assinar: é ele que fala com a"
echo "Certisign e pede PIN e OTP. Sem ele o certificado aparece, mas a"
echo "assinatura falha."
