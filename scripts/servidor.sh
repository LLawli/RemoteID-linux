#!/usr/bin/env bash
# O binário para servidores: o `remoteid` sem a janela, ligado estaticamente
# ao musl, que roda em qualquer Linux x86_64 sem depender de nada instalado
# (medido em 2026-11-13: RHEL/Rocky 8, Ubuntu 20.04, Debian 11 e Alpine). Vai
# sem o módulo PKCS#11: um `.so` musl não carrega num p11-kit com glibc.
#
# Compila dentro do rust:1.92-alpine. Na CI o job já roda nele; fora dele, o
# script se chama de novo num contêiner. Sai em target/servidor/.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGEM=rust:1.92-alpine
TARBALL=remoteid-servidor-x86_64.tar.gz

if [ ! -f /etc/alpine-release ]; then
    # O target/ pode ser um link para outro disco: o contêiner monta o destino.
    OBRA=$(realpath -m target/servidor)
    mkdir -p "$OBRA"
    docker run --rm -v "$PWD":/src:ro -v "$OBRA":/obra \
        -e OBRA=/obra -e CARGO_HOME=/obra/cargo -e CARGO_BUILD_JOBS -e DONO="$(id -u):$(id -g)" \
        -w /src "$IMAGEM" sh -c 'apk add -q bash && bash scripts/servidor.sh >/dev/null'
    echo "$OBRA/$TARBALL"
    exit
fi

# O tar do busybox não ordena nem fixa dono, e o readelf vem do binutils.
apk add -q musl-dev tar binutils

OBRA=${OBRA:-$PWD/target/servidor}
mkdir -p "$OBRA"
CARGO_TARGET_DIR="$OBRA" cargo build --release --locked --no-default-features --bin remoteid
programa="$OBRA/release/remoteid"
# Estático de verdade: nenhum interpretador nem biblioteca dinâmica.
if readelf -lW "$programa" 2>/dev/null | grep -q 'Requesting program interpreter' ||
    ldd "$programa" 2>&1 | grep -q '=>'; then
    echo "o $programa não saiu estático" >&2
    exit 1
fi

rm -rf "$OBRA/pacote"
install -Dm755 "$programa" "$OBRA/pacote/bin/remoteid"
# Sem data nem dono no pacote: reempacotar o mesmo build dá o mesmo arquivo.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
    -C "$OBRA/pacote" -c bin | gzip -n > "$OBRA/$TARBALL"
# Fora da CI, o contêiner roda como root: os arquivos voltam para quem chamou.
[ -z "${DONO:-}" ] || chown -R "$DONO" "$OBRA"
echo "$OBRA/$TARBALL"
