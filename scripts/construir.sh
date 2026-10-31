#!/usr/bin/env bash
# Constrói a extensão e a instala (--user), como quem instala de um remote.
#
# Exporta para um repositório local e instala dele, como as outras extensões
# do Âncora: é o caminho de quem usa, e o mesmo repo/ serve de remote do
# projeto.
#
#   scripts/construir.sh            constrói e instala
#   scripts/construir.sh --repo DIR só exporta para DIR (o remote do projeto)
set -euo pipefail
cd "$(dirname "$0")/.."
ID=dev.lukakuuhaku.Ancora.Driver.RemoteID
REPO=repo
INSTALAR=sim
if [ "${1:-}" = --repo ]; then
    REPO=${2:?informe o diretório do repositório}
    INSTALAR=nao
fi

# O estado e o build moram juntos: o flatpak-builder recusa os dois em sistemas
# de arquivos diferentes, e o .flatpak-builder pode ser um link para outro
# disco.
OBRA=.flatpak-builder
mkdir -p "$OBRA"
flatpak run org.flatpak.Builder --force-clean --disable-rofiles-fuse \
    --state-dir="$OBRA/estado" --repo="$REPO" "$OBRA/build" "$ID.yml"
# Gera o appstream que dá nome e descrição à extensão na busca do Âncora.
flatpak build-update-repo "$REPO" >/dev/null
[ "$INSTALAR" = sim ] || exit 0

REMOTO=$(echo "$ID" | tr '[:upper:]' '[:lower:]' | tr . -)-local
flatpak remote-add --user --no-gpg-verify --if-not-exists "$REMOTO" "file://$PWD/$REPO"
flatpak install --user --noninteractive -y --reinstall "$REMOTO" "$ID"
