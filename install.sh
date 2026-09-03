#!/bin/sh
# Bootstrap do harness DesktopID-linux: obtém o binário e roda o fluxo de teste.
#
# Uso rápido (um comando):
#   curl -fsSL https://raw.githubusercontent.com/LLawli/DesktopID-linux/main/install.sh | sh
#
# Ordem de tentativa:
#   1. binário pronto da última release (rápido, nada a compilar);
#   2. compilar do código-fonte, se houver `cargo`;
#   3. explicar como instalar o Rust, e oferecer o rustup.
#
# Nada é instalado no sistema fora do cache do usuário. Ao final, o relatório
# fica em ~/Downloads.
#
# Detalhe importante: mesmo chamado por `curl | sh`, o harness é interativo
# (pede e-mail, senha, PIN e o código do autenticador). Este script cuida disso
# reconectando a entrada ao terminal (/dev/tty); por isso NÃO rode dentro de um
# pipe que já consumiu o tty (ex.: outro `| sh` aninhado).
set -eu

REPO="${REMOTEID_REPO:-LLawli/DesktopID-linux}"
REF="${REMOTEID_REF:-main}"

# O build do Rust ocupa centenas de MB. Ele vai para o cache em DISCO, nunca
# para /tmp: em boa parte das distribuições /tmp é tmpfs, ou seja, RAM, e um
# alvo de compilação lá dentro consome memória da máquina do testador.
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/remoteid-linux"

say() { printf '%s\n' "$*" >&2; }
die() { say "erro: $*"; exit 1; }

# Testa se /dev/tty é REALMENTE abrível. Existir e passar no `-r` não basta:
# numa sessão sem terminal de controle o arquivo está lá e abrir dá ENXIO.
#
# O teste roda numa SUBSHELL de propósito. A forma óbvia, `{ : </dev/tty; }`,
# é uma armadilha: `:` é um special builtin, e pela POSIX um erro de
# redirecionamento num special builtin ENCERRA o shell não-interativo. O
# resultado é o script morrer calado em vez de cair no ramo alternativo. Dentro
# de uma subshell, o erro derruba só a subshell e o pai lê o status.
tem_tty() { (exec </dev/tty) 2>/dev/null; }

perguntar() {  # perguntar <texto>; devolve 0 para sim
    tem_tty || return 1
    printf '%s [s/N] ' "$1" >&2
    read -r resposta </dev/tty || return 1
    case "$resposta" in [sSyY]*) return 0 ;; *) return 1 ;; esac
}

fetch() {  # fetch <url> <destino>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "nem curl nem wget disponíveis."
    fi
}

# --- 1. binário pronto da última release ----------------------------------

alvo_da_maquina() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64-linux" ;;
        aarch64|arm64)  echo "aarch64-linux" ;;
        *)              echo "" ;;
    esac
}

BIN=""
ALVO="$(alvo_da_maquina)"
if [ -n "$ALVO" ] && [ "${REMOTEID_SEM_RELEASE:-}" != "1" ]; then
    mkdir -p "$CACHE/bin"
    CANDIDATO="$CACHE/bin/desktopid"
    URL="https://github.com/$REPO/releases/latest/download/remoteid-$ALVO"
    say "procurando binário pronto para $ALVO..."
    if fetch "$URL" "$CANDIDATO.tmp" 2>/dev/null; then
        chmod +x "$CANDIDATO.tmp"
        # Existir não basta: um HTML de erro 404 salvo em disco também
        # "existe". Só aceita se o binário roda de verdade.
        if "$CANDIDATO.tmp" --help >/dev/null 2>&1; then
            mv "$CANDIDATO.tmp" "$CANDIDATO"
            BIN="$CANDIDATO"
            say "binário pronto obtido."
        else
            rm -f "$CANDIDATO.tmp"
            say "o que veio da release não executa aqui; vou compilar."
        fi
    else
        say "sem release publicada para $ALVO; vou compilar."
    fi
fi

# --- 2. compilar do código-fonte ------------------------------------------

if [ -z "$BIN" ]; then
    if ! command -v cargo >/dev/null 2>&1; then
        # O cargo pode estar instalado mas fora do PATH desta sessão.
        [ -r "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        say ""
        say "Este programa é escrito em Rust e não há binário pronto para a sua"
        say "máquina, então é preciso compilá-lo. Falta o compilador (cargo)."
        say ""
        say "Pelo gerenciador da sua distribuição:"
        say "  Debian/Ubuntu : sudo apt install cargo"
        say "  Fedora        : sudo dnf install cargo"
        say "  Arch/Manjaro  : sudo pacman -S rust"
        say ""
        if perguntar "Prefere que eu instale o Rust para o seu usuário, via rustup (não mexe no sistema)?"; then
            fetch "https://sh.rustup.rs" "$CACHE/rustup.sh" || die "falha ao baixar o rustup."
            sh "$CACHE/rustup.sh" -y --no-modify-path --profile minimal </dev/tty \
                || die "o rustup não concluiu."
            . "$HOME/.cargo/env"
        else
            die "instale o cargo e rode este comando de novo."
        fi
    fi
    command -v cargo >/dev/null 2>&1 || die "cargo continua indisponível."

    # Achar o `cargo` no PATH não prova que ele roda: quando é um atalho do
    # rustup e não há toolchain padrão configurado, ele existe e falha. Sem esta
    # checagem o erro só apareceria lá na frente, disfarçado de "a compilação
    # falhou", mandando o testador investigar o lugar errado.
    if ! cargo --version >/dev/null 2>&1; then
        if command -v rustup >/dev/null 2>&1; then
            say "o cargo está instalado pelo rustup, mas sem toolchain padrão."
            if perguntar "Configuro a stable agora (rustup default stable)?"; then
                rustup default stable </dev/tty || die "o rustup não configurou a stable."
            else
                die "rode 'rustup default stable' e tente de novo."
            fi
        else
            die "o cargo está no PATH mas não executa. Reinstale o Rust."
        fi
    fi
    cargo --version >/dev/null 2>&1 || die "o cargo continua sem rodar."

    SRC="$CACHE/src"
    rm -rf "$SRC"; mkdir -p "$SRC"
    say "baixando $REPO@$REF..."
    fetch "https://codeload.github.com/$REPO/tar.gz/$REF" "$CACHE/src.tgz" \
        || die "falha ao baixar. Confira REMOTEID_REPO/REMOTEID_REF e a conexão."
    tar -xzf "$CACHE/src.tgz" --strip-components=1 -C "$SRC" \
        || die "falha ao extrair o pacote."
    [ -f "$SRC/Cargo.toml" ] || die "pacote sem Cargo.toml (repo/ref errado?)."

    say ""
    say "compilando (a primeira vez leva alguns minutos; as seguintes são rápidas)..."
    # O alvo fica no cache, fora do diretório de fontes: reaproveitado entre
    # execuções e, de novo, em disco e não em tmpfs.
    CARGO_TARGET_DIR="$CACHE/target" cargo build --release --manifest-path "$SRC/Cargo.toml" \
        || die "a compilação falhou. Mande a saída acima para quem pediu o teste."
    BIN="$CACHE/target/release/desktopid"
    [ -x "$BIN" ] || die "compilou mas não achei o binário em $BIN."
fi

# --- 3. rodar, reconectando ao terminal para os prompts funcionarem -------

say ""
say "=== iniciando o harness (o relatório será salvo em ~/Downloads) ==="
say ""
if tem_tty; then
    exec "$BIN" harness </dev/tty
else
    say "aviso: sem terminal interativo; as etapas que pedem dados vão ser puladas."
    exec "$BIN" harness
fi
