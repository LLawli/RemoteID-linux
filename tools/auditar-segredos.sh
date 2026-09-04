#!/usr/bin/env bash
# Barreira contra publicar segredo. Roda sobre os arquivos VERSIONADOS (o que o
# GitHub veria), não sobre o diretório de trabalho.
#
# O que ele procura não é genérico: é o que ESTE projeto pode vazar. PIN e OTP
# do certificado, o sessionToken, a chave da instalação, o estado local e os
# runs reais do harness (que identificam o titular: CPF, nome, e-mail).
#
# Uso: tools/auditar-segredos.sh
set -uo pipefail
cd "$(dirname "$0")/.."

ACHADOS=0
vermelho() { printf '\033[31m%s\033[0m\n' "$*"; }
verde()    { printf '\033[32m%s\033[0m\n' "$*"; }

# Isenções, uma a uma, com o motivo. NÃO é para crescer sem justificativa: cada
# caminho aqui é um lugar onde um valor em claro é a ENTRADA de um teste que
# prova a redação, ou um exemplo do algoritmo na documentação. Se a lista virar
# um curinga, o guard deixa de guardar.
#
# `exigir_isencoes_vivas` reprova quando um caminho isento some: allowlist que
# aponta para arquivo inexistente é allowlist podre, e some junto com a proteção.
ISENTOS_VALOR_EM_CLARO=(
    'crates/remoteid-redacao/src/lib.rs'              # testes da própria redação
    'crates/remoteid-protocolo-servidor/src/canonical.rs'  # teste da canonicalização
    'docs/PAYLOADS.md'                               # exemplo do algoritmo
)

exigir_isencoes_vivas() {
    local caminho
    for caminho in "${ISENTOS_VALOR_EM_CLARO[@]}"; do
        if ! git ls-files --error-unmatch "$caminho" >/dev/null 2>&1; then
            vermelho "✗ isenção podre: $caminho não é mais versionado"
            echo "    Remova a entrada de ISENTOS_VALOR_EM_CLARO neste script."
            ACHADOS=$((ACHADOS + 1))
        fi
    done
}

# acusar <descrição> <regex> [--isentar] — falha se o padrão aparecer em arquivo
# versionado. Com `--isentar`, pula os caminhos de ISENTOS_VALOR_EM_CLARO.
acusar() {
    local descricao="$1" regex="$2" isentar="${3:-}"
    local excecoes=(':!tools/auditar-segredos.sh')
    if [ "$isentar" = "--isentar" ]; then
        local caminho
        for caminho in "${ISENTOS_VALOR_EM_CLARO[@]}"; do
            excecoes+=(":!$caminho")
        done
    fi
    local hits
    hits="$(git grep -nIE "$regex" -- . "${excecoes[@]}" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        vermelho "✗ $descricao"
        printf '%s\n' "$hits" | head -5 | sed 's/^/    /'
        ACHADOS=$((ACHADOS + 1))
    else
        verde "✓ $descricao"
    fi
}

# proibir_arquivo <descrição> <regex de caminho>
proibir_arquivo() {
    local descricao="$1" regex="$2"
    local hits
    hits="$(git ls-files | grep -E "$regex" || true)"
    if [ -n "$hits" ]; then
        vermelho "✗ $descricao"
        printf '%s\n' "$hits" | head -5 | sed 's/^/    /'
        ACHADOS=$((ACHADOS + 1))
    else
        verde "✓ $descricao"
    fi
}

echo "Auditando $(git ls-files | wc -l) arquivos versionados…"

# PIN e OTP em claro. A forma que importa é a do JSON do diagnóstico e a dos
# payloads: `"pin":"1234"`. O valor redigido (`<redigido>`) não casa.
acusar 'nenhum "pin" com valor em claro'  '"pin"[[:space:]]*:[[:space:]]*"[0-9]' --isentar
acusar 'nenhum "otp" com valor em claro'  '"otp"[[:space:]]*:[[:space:]]*"[0-9]' --isentar
acusar 'nenhuma "senha"/"password" literal' '"(senha|password)"[[:space:]]*:[[:space:]]*"[^"<]' --isentar
exigir_isencoes_vivas

# sessionToken e Bearer só podem aparecer como impressão digital.
acusar 'nenhum sessionToken em claro' '"sessionToken"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/]{20,}'
acusar 'nenhum JWT'                   'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'

# Chave privada de verdade. As fixtures do mock são sintéticas e vivem só em
# crates/remoteid-mock/fixtures/ — qualquer chave FORA dali é suspeita.
CHAVES="$(git grep -lE 'BEGIN (RSA |EC )?PRIVATE KEY' -- . \
    ':!crates/remoteid-mock/fixtures' ':!tools/auditar-segredos.sh' 2>/dev/null || true)"
if [ -n "$CHAVES" ]; then
    vermelho "✗ chave privada versionada fora das fixtures do mock"
    printf '%s\n' "$CHAVES" | sed 's/^/    /'
    ACHADOS=$((ACHADOS + 1))
else
    verde "✓ nenhuma chave privada fora das fixtures do mock"
fi

# Arquivos que nunca podem entrar, mesmo que o .gitignore falhe.
proibir_arquivo 'nenhum state.json versionado'          '(^|/)state\.json$'
proibir_arquivo 'nenhuma chave de instalação versionada' '\.installation-key\.pem$'
proibir_arquivo 'nenhum run do harness versionado'       '(desktopid|remoteid)-harness-.*\.txt$'
proibir_arquivo 'nenhum .logs/ ou vendor/ versionado'    '^(\.logs|vendor)/'
proibir_arquivo 'nenhum diretório diag/ versionado'      '(^|/)diag/'

echo
if [ "$ACHADOS" -gt 0 ]; then
    vermelho "AUDITORIA REPROVADA: $ACHADOS categoria(s) com achado."
    echo "Nada é publicado até isso zerar. Se for falso positivo, ajuste o padrão"
    echo "aqui e explique no commit por que aquele caso é seguro."
    exit 1
fi
verde "AUDITORIA APROVADA: nenhum segredo nos arquivos versionados."
