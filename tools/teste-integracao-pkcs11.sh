#!/usr/bin/env bash
# Teste de integração PONTA A PONTA do módulo PKCS#11, sem intervenção humana.
#
# Prova a cadeia inteira que nenhum teste unitário alcança:
#
#   pkcs11-tool (hospedeiro real, fora do nosso código)
#     → libremoteid_pkcs11.so  (o cdylib, carregado pelo hospedeiro)
#       → socket UNIX
#         → Servico            (via `servidor-fixo`: o app menos a UI)
#           → servidor RemoteID FALSO (remoteid-mock)
#
# O único elo que fica de fora é o diálogo GTK de PIN/OTP: não há como um gate
# não-interativo digitar num diálogo. O `servidor-fixo` substitui EXATAMENTE
# essa peça (o `Prompter`) por `FatoresFixos`, e nada mais — o motor, o cache
# de sessão, o protocolo do socket e o do servidor são os de produção.
#
# Uso:  tools/teste-integracao-pkcs11.sh
# Saída: exit 0 só se TODAS as asserções passarem. Feito para ser um gate.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$RAIZ"
DIR_ESTADO="/tmp/remoteid-teste"   # espelha remoteid_caminhos::DIR_TESTE
PIN_TESTE=1234                     # fixture sintética do remoteid-mock, não é segredo
OTP_TESTE=123456

TRABALHO="$(mktemp -d)"
MOCK_PID=""
SRV_PID=""
PASSOS=0

vermelho() { printf '\033[31m%s\033[0m\n' "$*"; }
verde()    { printf '\033[32m%s\033[0m\n' "$*"; }

falhar() { vermelho "FALHOU: $*"; exit 1; }
ok()     { PASSOS=$((PASSOS + 1)); verde "  ✓ $*"; }
passo()  { printf '\n→ %s\n' "$*"; }

limpar() {
    local status=$?
    [ -n "$SRV_PID" ]  && kill "$SRV_PID"  2>/dev/null || true
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TRABALHO"
    return $status
}
trap limpar EXIT

# --------------------------------------------------------------- pré-requisitos
passo "conferindo as ferramentas externas"
for prog in pkcs11-tool openssl; do
    command -v "$prog" >/dev/null || falhar "'$prog' não está instalado (pacotes: opensc, openssl)"
done
ok "pkcs11-tool e openssl presentes"

# Um ambiente de teste local no ar usaria o MESMO state.json e o MESMO socket:
# apagar por baixo dele quebraria os dois. Aborta em vez de brigar.
if [ -S "$DIR_ESTADO/remoteid.sock" ] && ss -xl 2>/dev/null | grep -qF "$DIR_ESTADO/remoteid.sock"; then
    falhar "há um ambiente de teste local no ar ($DIR_ESTADO/remoteid.sock). Encerre o tools/teste-local.sh antes."
fi

# --------------------------------------------------------------- build
passo "compilando os artefatos"
cargo build -q -p remoteid-mock -p remoteid-cli -p remoteid-pkcs11
cargo build -q -p remoteid-daemon --example servidor-fixo

# Código de saída não é prova: confere o artefato de verdade. O cdylib é o que
# o hospedeiro carrega; um .so ausente ou de 2 KB passaria despercebido num
# `cargo build` verde e só explodiria dentro do pkcs11-tool.
MODULO="$RAIZ/target/debug/libremoteid_pkcs11.so"
[ -f "$MODULO" ] || falhar "o cdylib não foi gerado em $MODULO"
TAM="$(stat -c%s "$MODULO")"
[ "$TAM" -gt 100000 ] || falhar "o cdylib tem $TAM bytes, tamanho implausível para o módulo"
for bin in remoteid-mock remoteid; do
    [ -x "$RAIZ/target/debug/$bin" ] || falhar "binário ausente: target/debug/$bin"
done
[ -x "$RAIZ/target/debug/examples/servidor-fixo" ] || falhar "exemplo servidor-fixo não foi gerado"
ok "cdylib com $TAM bytes, mais os binários mock/cli/servidor-fixo"

# --------------------------------------------------------------- mock
passo "subindo o servidor RemoteID FALSO"
# Porta efêmera: o gate não pode colidir com nada que o dev tenha aberto.
PORTA="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
URL="http://localhost:$PORTA"

rm -rf "$DIR_ESTADO"
"$RAIZ/target/debug/remoteid-mock" "$PORTA" >"$TRABALHO/mock.log" 2>&1 &
MOCK_PID=$!
porta_viva() { (exec 3<>"/dev/tcp/127.0.0.1/$PORTA") 2>/dev/null; }
for _ in $(seq 1 50); do
    if porta_viva; then break; fi
    sleep 0.1
done
porta_viva || falhar "o mock não subiu em $URL"
ok "mock ouvindo em $URL"

export TEST_URL="$URL"   # o interruptor único: reloca estado, diag e socket para /tmp

passo "preparando a conta de teste (login + registro + carteira)"
REMOTEID_EMAIL=teste@remoteid.local REMOTEID_SENHA=teste-1234 \
    "$RAIZ/target/debug/remoteid" preparar >"$TRABALHO/preparar.log" 2>&1 \
    || { cat "$TRABALHO/preparar.log"; falhar "o 'remoteid preparar' não completou"; }
grep -q 'certificado: serial' "$TRABALHO/preparar.log" || falhar "a carteira não trouxe certificado"
ok "conta preparada em $DIR_ESTADO"

# --------------------------------------------------------------- socket
passo "subindo o servidor do socket (Servico real, PIN/OTP fixos)"
FIXO_PIN="$PIN_TESTE" FIXO_OTP="$OTP_TESTE" \
    "$RAIZ/target/debug/examples/servidor-fixo" >"$TRABALHO/servidor.log" 2>&1 &
SRV_PID=$!
SOCK="$DIR_ESTADO/remoteid.sock"
for _ in $(seq 1 50); do
    if [ -S "$SOCK" ]; then break; fi
    sleep 0.1
done
[ -S "$SOCK" ] || { cat "$TRABALHO/servidor.log"; falhar "o socket não apareceu em $SOCK"; }
ok "socket em $SOCK"

# O socket é o canal por onde passa uma ordem de assinar: 0600 não é estética.
PERM="$(stat -c%a "$SOCK")"
[ "$PERM" = "600" ] || falhar "o socket está com permissão $PERM, esperado 600"
ok "permissão do socket 0600"

# --------------------------------------------------------------- token
passo "inspecionando o token pelo pkcs11-tool"
p11() { timeout 60 pkcs11-tool --module "$MODULO" "$@"; }

p11 -L >"$TRABALHO/slots.txt" 2>&1 || { cat "$TRABALHO/slots.txt"; falhar "C_GetSlotList/C_GetTokenInfo"; }
grep -q 'RemoteID Certisign' "$TRABALHO/slots.txt" || falhar "o token não se apresentou como 'RemoteID Certisign'"
ok "slot presente: $(grep -m1 'token label' "$TRABALHO/slots.txt" | sed 's/.*: //')"

p11 -M >"$TRABALHO/mecanismos.txt" 2>&1 || falhar "C_GetMechanismList"
grep -q 'SHA256-RSA-PKCS' "$TRABALHO/mecanismos.txt" || falhar "SHA256-RSA-PKCS não é anunciado"
grep -q 'RSA-PKCS'        "$TRABALHO/mecanismos.txt" || falhar "RSA-PKCS não é anunciado"
ok "mecanismos anunciados: RSA-PKCS e SHA256-RSA-PKCS"
# `encrypt` no RSA-PKCS é o CKF_ENCRYPT: o gate do SunPKCS11 para registrar o
# `Cipher` de RSA (issue #10). Ancorado no início da linha para não casar com o
# SHA256-RSA-PKCS, que é só assinatura.
grep -Eq '^[[:space:]]*RSA-PKCS,.*encrypt' "$TRABALHO/mecanismos.txt" \
    || falhar "RSA-PKCS não anuncia encrypt (CKF_ENCRYPT); o SunPKCS11 não registraria o Cipher"
grep -Eq '^[[:space:]]*SHA256-RSA-PKCS,.*encrypt' "$TRABALHO/mecanismos.txt" \
    && falhar "SHA256-RSA-PKCS anuncia encrypt, e é mecanismo só de assinatura"
ok "RSA-PKCS anuncia encrypt; SHA256-RSA-PKCS não"

p11 -O >"$TRABALHO/objetos.txt" 2>&1 || falhar "C_FindObjects"
grep -q 'Certificate Object' "$TRABALHO/objetos.txt" || falhar "o token não publicou o certificado"
grep -q 'Public Key Object'  "$TRABALHO/objetos.txt" || falhar "o token não publicou a chave pública"
# Sem ancorar o prefixo, o `.*:` guloso comeria o próprio ID (ac:e8:…:0f) e
# sobraria só o último octeto.
ID_CERT="$(grep -m1 '^  ID:' "$TRABALHO/objetos.txt" | sed 's/^  ID: *//; s/://g')"
[ -n "$ID_CERT" ] || falhar "não consegui extrair o CKA_ID do certificado"
ok "certificado e chave pública publicados (CKA_ID $ID_CERT)"

# A chave pública sai do CERTIFICADO lido pelo próprio módulo: se o módulo
# publicasse um par que não casa com o certificado, o verify abaixo reprovaria.
p11 --read-object --type cert --id "$ID_CERT" -o "$TRABALHO/cert.der" >/dev/null 2>&1 \
    || falhar "C_GetAttributeValue(CKA_VALUE) do certificado"
openssl x509 -inform DER -in "$TRABALHO/cert.der" -noout -pubkey >"$TRABALHO/pub.pem" 2>/dev/null \
    || falhar "o CKA_VALUE do certificado não é um X.509 DER válido"
ok "certificado lido do token e parseado pelo openssl"

# --------------------------------------------------------------- cifra
# C_EncryptInit/C_Encrypt com a chave PÚBLICA: cifra local, PKCS#1 v1.5, sem
# socket e sem PIN. A prova é a chave privada FALSA do mock (a que assina o
# certificado falso) decifrar o que o módulo cifrou.
passo "cifra com a chave pública (C_Encrypt, local)"
printf 'bloco curto para a cifra' >"$TRABALHO/claro.bin"
p11 --encrypt -m RSA-PKCS --id "$ID_CERT" -i "$TRABALHO/claro.bin" -o "$TRABALHO/cifrado.bin" \
    >"$TRABALHO/encrypt.log" 2>&1 || { cat "$TRABALHO/encrypt.log"; falhar "C_Encrypt falhou"; }
TAM_CIFRA="$(stat -c%s "$TRABALHO/cifrado.bin")"
[ "$TAM_CIFRA" -eq 256 ] || falhar "bloco cifrado com $TAM_CIFRA bytes, esperado 256"
openssl pkeyutl -decrypt -inkey crates/remoteid-mock/fixtures/fake-key.pem \
    -in "$TRABALHO/cifrado.bin" -out "$TRABALHO/decifrado.bin" 2>/dev/null \
    || falhar "a chave falsa do mock não decifrou o bloco do C_Encrypt"
cmp -s "$TRABALHO/claro.bin" "$TRABALHO/decifrado.bin" \
    || falhar "o decifrado difere do texto claro"
ok "256 bytes, decifrados pela chave privada do certificado"

# --------------------------------------------------------------- assinatura
printf 'conteudo de teste do gate de integracao' >"$TRABALHO/dados.txt"

assinar() {
    p11 --sign -m SHA256-RSA-PKCS -i "$TRABALHO/dados.txt" -o "$1" >"$TRABALHO/sign.log" 2>&1 \
        || { cat "$TRABALHO/sign.log"; falhar "C_Sign falhou ($1)"; }
    local n; n="$(stat -c%s "$1")"
    [ "$n" -eq 256 ] || falhar "assinatura com $n bytes, esperado 256 (RSA-2048 cru)"
    openssl dgst -sha256 -verify "$TRABALHO/pub.pem" -signature "$1" "$TRABALHO/dados.txt" >/dev/null \
        || falhar "a assinatura NÃO confere com a chave pública do certificado"
}

passo "primeira assinatura (sem cache: exige PIN+OTP)"
assinar "$TRABALHO/sig1.bin"
ok "256 bytes, 'Verified OK' contra a pubkey do certificado"

# O diag do servidor tem o pid no nome: pega o arquivo DESTE processo, não o
# mais recente (o `remoteid preparar` também escreveu um).
DIAG="$(ls "$DIR_ESTADO"/diag/run-*-"$SRV_PID".jsonl 2>/dev/null | head -1 || true)"
[ -n "$DIAG" ] || falhar "não achei o diag do servidor (pid $SRV_PID) em $DIR_ESTADO/diag"
grep -q '"rotulo":"tokensessao (pin+otp)"' "$DIAG" || falhar "a 1ª assinatura não emitiu tokensessao"
grep -q '"evento":"assinatura.sessao_nova"' "$DIAG" || falhar "a 1ª assinatura não gravou sessão nova"
ok "emitiu tokensessao e gravou a sessão nova"

passo "segunda assinatura (deve reusar a sessão em cache, sem PIN+OTP)"
TOKENS_ANTES="$(grep -c '"rotulo":"tokensessao (pin+otp)"' "$DIAG" || true)"
assinar "$TRABALHO/sig2.bin"
grep -q '"evento":"assinatura.cache_hit"' "$DIAG" || falhar "a 2ª assinatura não registrou cache_hit"
TOKENS_DEPOIS="$(grep -c '"rotulo":"tokensessao (pin+otp)"' "$DIAG" || true)"
[ "$TOKENS_ANTES" -eq "$TOKENS_DEPOIS" ] \
    || falhar "a 2ª assinatura reemitiu tokensessao ($TOKENS_ANTES → $TOKENS_DEPOIS); o cache não pegou"
ok "cache_hit, sem novo tokensessao, e assinatura válida"

# --------------------------------------------------------------- modo cru
# O que o PJeOffice manda para autenticar: um DigestInfo(MD5) de 34 bytes pelo
# CKM_RSA_PKCS. O módulo repassa o bloco inteiro com `algorithm: ""` (issue
# #11), o servidor (aqui, o mock) só aplica o padding, e a assinatura verifica
# como MD5withRSA contra a chave pública do certificado. É o caso 4 da sondagem
# de 05/09/2026, reproduzido de ponta a ponta sem Java.
passo "assinatura crua (CKM_RSA_PKCS com DigestInfo(MD5), o caminho do PJeOffice)"
{
    printf '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'
    openssl dgst -md5 -binary "$TRABALHO/dados.txt"
} >"$TRABALHO/digestinfo-md5.bin"
[ "$(stat -c%s "$TRABALHO/digestinfo-md5.bin")" -eq 34 ] || falhar "DigestInfo(MD5) montado errado"
p11 --sign -m RSA-PKCS -i "$TRABALHO/digestinfo-md5.bin" -o "$TRABALHO/sig-md5.bin" \
    >"$TRABALHO/sign-md5.log" 2>&1 || { cat "$TRABALHO/sign-md5.log"; falhar "C_Sign cru falhou"; }
[ "$(stat -c%s "$TRABALHO/sig-md5.bin")" -eq 256 ] || falhar "assinatura crua sem 256 bytes"
openssl dgst -md5 -verify "$TRABALHO/pub.pem" -signature "$TRABALHO/sig-md5.bin" "$TRABALHO/dados.txt" >/dev/null \
    || falhar "a assinatura crua NÃO verifica como MD5withRSA: o bloco não foi assinado inteiro"
grep -q '"algorithm":""' "$DIAG" || falhar "o requestHash do modo cru não foi com algorithm vazio"
ok "DigestInfo(MD5) assinado cru pelo servidor, 'Verified OK' como MD5withRSA"

# --------------------------------------------------------------- java
# O critério de aceitação da issue #10, na mesma cadeia (módulo → socket →
# servidor-fixo → mock) e pela porta que o PJeOffice usa: o `Cipher` do
# SunPKCS11. Sem Java na máquina o passo é pulado; no CI ele é obrigatório (o
# runner ubuntu-24.04 traz o Temurin 11 em JAVA_HOME_11_X64, a mesma versão da
# JRE que o PJeOffice embarca).
passo "prova em Java: o Cipher do SunPKCS11 (critério de aceitação da issue #10)"
JAVA=""
if [ -n "${JAVA_HOME_11_X64:-}" ] && [ -x "$JAVA_HOME_11_X64/bin/java" ]; then
    JAVA="$JAVA_HOME_11_X64/bin/java"
elif command -v java >/dev/null; then
    JAVA="$(command -v java)"
fi
if [ -z "$JAVA" ]; then
    [ -z "${CI:-}" ] || falhar "sem java no runner: a prova JCA é obrigatória no CI"
    echo "  (pulado: sem java nesta máquina; o CI roda com o Temurin 11 do runner)"
else
    # `--md5`: o passo que reproduz o PjeAuthenticatorTask (DigestInfo(MD5)
    # pelo Cipher, verificado como MD5withRSA), que depende do modo cru.
    "$JAVA" tools/prova-jca-pkcs11/ProvaCipher.java "$MODULO" --md5 >"$TRABALHO/java.log" 2>&1 \
        || { cat "$TRABALHO/java.log"; falhar "a prova JCA reprovou"; }
    grep -q 'Cipher.RSA/ECB/PKCS1Padding registrado' "$TRABALHO/java.log" \
        || { cat "$TRABALHO/java.log"; falhar "a prova JCA não confirmou o Cipher"; }
    grep -q 'verifica como MD5withRSA' "$TRABALHO/java.log" \
        || { cat "$TRABALHO/java.log"; falhar "a prova JCA não fechou o MD5withRSA"; }
    ok "SunPKCS11 registrou o Cipher; SHA256withRSA e MD5withRSA verificam pela porta do PJeOffice"
fi

# --------------------------------------------------------------- segredos
# Regra de domínio, não detalhe: PIN e OTP são permanentes/sensíveis e o diag é
# um arquivo que o usuário anexa num relatório de bug. Se a redação regredir,
# este gate tem de ficar vermelho.
passo "conferindo que o diag não vazou PIN nem OTP"
grep -q '"pin":"<redigido>"' "$DIAG" || falhar "o campo pin não saiu redigido no diag"
grep -q '"otp":"<redigido>"' "$DIAG" || falhar "o campo otp não saiu redigido no diag"
for arquivo in "$DIR_ESTADO"/diag/*.jsonl; do
    if grep -q "\"pin\":\"$PIN_TESTE\"" "$arquivo"; then falhar "PIN em claro em $arquivo"; fi
    if grep -q "\"otp\":\"$OTP_TESTE\"" "$arquivo"; then falhar "OTP em claro em $arquivo"; fi
done
ok "pin e otp redigidos, nenhum valor em claro no diag"

printf '\n'
verde "TESTE DE INTEGRAÇÃO PKCS#11: $PASSOS asserções, todas verdes."
echo "Não coberto (exige humano): o diálogo GTK de PIN/OTP. Tudo abaixo dele foi exercitado."
