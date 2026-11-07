#!/usr/bin/env bash
# O binário da release: o módulo e o programa compilados no SDK do GNOME 51, o
# mesmo runtime que os hospedeiros usam, num tarball com `lib/` e `bin/` na
# raiz. Sai em target/sdk/, e o nome não muda de uma versão para outra.
#
# Precisa de org.gnome.Sdk//51 e de org.freedesktop.Sdk.Extension.rust-stable//26.08.
set -euo pipefail
cd "$(dirname "$0")/.."
SDK=org.gnome.Sdk//51
TARBALL=remoteid-x86_64.tar.gz

# O target/ pode ser um link para outro disco, e o sandbox não segue links.
OBRA=$(realpath -m target/sdk)
mkdir -p "$OBRA"
# O sandbox não vê o $HOME: sem CARGO_HOME, cada build baixaria tudo de novo.
flatpak run --share=network --filesystem="$PWD" --filesystem="$OBRA" \
    --env=CARGO_HOME="$OBRA/cargo" --env=CARGO_TARGET_DIR="$OBRA" \
    --command=sh "$SDK" -c '
        set -eu
        . /usr/lib/sdk/rust-stable/enable.sh
        cargo build --release --locked
        ! ldd "$CARGO_TARGET_DIR"/release/remoteid "$CARGO_TARGET_DIR"/release/libremoteid.so | grep "not found"
    '

rm -rf "$OBRA/pacote"
install -Dm755 "$OBRA/release/remoteid" "$OBRA/pacote/bin/remoteid"
install -Dm755 "$OBRA/release/libremoteid.so" "$OBRA/pacote/lib/libremoteid.so"
# Sem data nem dono no pacote: reempacotar o mesmo build dá o mesmo arquivo.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
    -C "$OBRA/pacote" -c bin lib | gzip -n > "$OBRA/$TARBALL"
echo "$OBRA/$TARBALL"
