#!/bin/sh
# Decompila funções do binário oficial de macOS por endereço. Uso:
#   tools/ghidra/decompile.sh 0x100065558 0x1000767a8 ...
#
# Atalho para `tools/ghidra/run.sh decomp.java <addrs>`; toda a mecânica
# (podman/docker, layout do vendor/, reuso do projeto Ghidra) está no run.sh.
set -eu
exec "$(dirname -- "$0")/run.sh" decomp.java "$@"
