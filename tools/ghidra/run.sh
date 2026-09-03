#!/bin/sh
# Roda um GhidraScript sobre o binário oficial de macOS, num contêiner efêmero.
# Uso:
#   tools/ghidra/run.sh <script.java> [args...]
#
# O projeto Ghidra fica em vendor/ghidra-proj (fora do git) e é REUSADO: a
# análise do binário leva ~75s e só acontece na primeira vez. Sem isso cada
# consulta pagaria a análise inteira de novo.
#
# Requer a imagem docker.io/blacktop/ghidra e o binário extraído do instalador
# oficial em vendor/ (ver docs/PROTOCOLO.md seção 8).
set -eu

HERE=$(cd -- "$(dirname -- "$0")/../.." && pwd)   # raiz do repo
[ "$#" -ge 1 ] || { echo "uso: $0 <script.java> [args...]" >&2; exit 1; }
SCRIPT=$1; shift

# O .pkg do macOS já veio com dois layouts diferentes conforme a versão.
for c in \
  "vendor/mac-intel/payload/desktopID.app/Contents/MacOS/desktopID" \
  "vendor/mac-intel/payload/desktopID.app/desktopID.app/Contents/MacOS/desktopID"
do
  [ -f "$HERE/$c" ] && { BIN_REL=$c; break; }
done
[ -n "${BIN_REL:-}" ] || {
  echo "binário do desktopID não encontrado em vendor/ — ver docs/PROTOCOLO.md §8" >&2
  exit 1
}

RT=${CONTAINER_RUNTIME:-}
[ -n "$RT" ] || for c in podman docker; do command -v "$c" >/dev/null 2>&1 && { RT=$c; break; }; done
[ -n "$RT" ] || { echo "nem podman nem docker no PATH" >&2; exit 1; }

IMG=${GHIDRA_IMAGE:-docker.io/blacktop/ghidra:latest}
PROJ=vendor/ghidra-proj
mkdir -p "$HERE/$PROJ"

[ -f "$HERE/$PROJ/desktopid.gpr" ] && MODE="-process desktopID -noanalysis" \
                                  || MODE="-import /w/$BIN_REL"

# Dono dos arquivos que o contêiner escreve em vendor/ghidra-proj. Além das
# permissões no host, o Ghidra grava o DONO dentro do projeto e recusa abrir um
# projeto de outro usuário ("NotOwnerException"), então os dois runtimes têm de
# entrar no contêiner com o mesmo uid. No podman rootless isso pede
# --userns=keep-id: sem ele o uid pedido cairia num subuid.
# Se o projeto for de outro dono, apague vendor/ghidra-proj: ele é descartável
# (a reimportação leva ~75s).
[ "$RT" = "podman" ] && AS_USER="--userns=keep-id --user $(id -u):$(id -g)" \
                     || AS_USER="--user $(id -u):$(id -g)"

exec "$RT" run --rm $AS_USER -e HOME=/tmp -v "$HERE:/w:z" "$IMG" \
  bash -lc "/ghidra/support/analyzeHeadless /w/$PROJ desktopid $MODE \
    -scriptPath /w/tools/ghidra -postScript '$SCRIPT' $* 2>&1 \
    | sed -n 's/^INFO  [^>]*> @@ //p' | sed 's/ (GhidraScript) *$//'"
