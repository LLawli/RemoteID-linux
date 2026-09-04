#!/usr/bin/env sh
# Desfaz o que o instalar.sh fez. Não toca em ~/.local/state/remoteid: o estado
# da instalação e a chave são seus, e apagá-los exigiria novo login e registro.
# Para removê-los, use `remoteid reinstalar` ou apague o diretório à mão.
set -eu
PREFIX="${PREFIX:-$HOME/.local}"
P11="${XDG_CONFIG_HOME:-$HOME/.config}/pkcs11/modules"

rm -fv "$PREFIX/bin/remoteid" "$PREFIX/bin/remoteid-app" \
       "$PREFIX/lib/remoteid/libremoteid_pkcs11.so" \
       "$PREFIX/share/applications/dev.lukakuuhaku.RemoteID.desktop" \
       "$PREFIX/share/icons/hicolor/scalable/apps/dev.lukakuuhaku.RemoteID.svg" \
       "$PREFIX/share/icons/hicolor/symbolic/apps/dev.lukakuuhaku.RemoteID-symbolic.svg" \
       "$P11/remoteid.module" 2>/dev/null || true
rmdir "$PREFIX/lib/remoteid" 2>/dev/null || true

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
echo "removido. O estado em ~/.local/state/remoteid foi PRESERVADO."
