#!/usr/bin/env bash
# Gera as fixtures SINTÉTICAS do remoteid-mock: uma AC de teste e o certificado
# de um titular emitido por ela.
#
# Por que existe: o certificado anterior era uma CA AUTOASSINADA com CA:TRUE e
# sem nenhuma extensão de titular. Isso não tem cara de e-CPF: um certificado de
# pessoa física da ICP-Brasil é folha (CA:FALSE), tem keyUsage com
# digitalSignature e nonRepudiation, e carrega os dados do titular em otherName
# no subjectAltName. Testar contra um certificado que não se parece com o real
# esconde justamente os bugs de parsing que aparecem em produção.
#
# NADA aqui certifica ninguém: a AC é inventada, não encadeia na raiz da
# ICP-Brasil, e o CPF é 00000000000.
#
# Uso: tools/gerar-fixtures-mock.sh [diretório-de-saída]
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
SAIDA="${1:-$RAIZ/crates/remoteid-mock/fixtures}"
mkdir -p "$SAIDA"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# O DN da AC tem de bater com a constante ISSUER do mock, que é a string que o
# servidor real devolveria no JSON da carteira. Sem OU, de propósito.
# Os DNs seguem a FORMA do certificado real (conferida num run do harness, sem
# copiar nenhum valor): o emissor tem OU, e o titular tem CINCO OUs. Um teste
# com um OU só esconderia bugs de quem itera sobre eles — e o app mostra os OUs
# na tela. Os valores aqui gritam TESTE de propósito.
DN_AC="/C=BR/O=ICP-Brasil TESTE/OU=AC TESTE RAIZ/CN=AC TESTE DESKTOPID"
DN_TITULAR="/C=BR/O=ICP-Brasil TESTE/OU=TESTES/OU=AC TESTE FALSA/OU=CERTIFICADO TESTE/OU=SEM VALOR JURIDICO/OU=A1 TESTE/CN=JOÃO GONÇALVES DE ASSUNÇÃO:11111111111"

# Campos da ICP-Brasil no subjectAltName. Os TAMANHOS saíram do certificado
# real (medidos com asn1parse num run do harness; nenhum valor foi copiado):
#
#   2.16.76.1.3.1      45 bytes  nascimento DDMMAAAA(8) + CPF(11) + NIS(11) + RG(15)
#   2.16.76.1.3.6      12 bytes  CEI
#   2.16.76.1.3.5      19 bytes  título de eleitor(12) + zona(3) + seção(4)
#   2.16.76.1.4.2.1.1   9 bytes  campo da própria AC
#
# 45, e não 51: o órgão expedidor NÃO entra neste campo. Errar isso produz um
# certificado que nenhum parser de tamanho fixo aceita — foi o primeiro erro
# desta fixture.
NASCIMENTO="01011990"
# 111.111.111-11: sequência repetida, rejeitada por qualquer validação de CPF.
# Fixture não pode carregar um CPF que passe na regra da Receita — alguém
# poderia tomar por real.
CPF="11111111111"
NIS="00000000000"
RG="000000000000000"
DADOS_PF="${NASCIMENTO}${CPF}${NIS}${RG}"
DADOS_CEI="000000000000"
DADOS_TITULO="0000000000000000000"
DADOS_AC="000000000"
confere_tam() { [ "${#2}" -eq "$3" ] || { echo "erro: campo $1 tem ${#2} bytes, esperado $3" >&2; exit 1; }; }
confere_tam 2.16.76.1.3.1     "$DADOS_PF"     45
confere_tam 2.16.76.1.3.6     "$DADOS_CEI"    12
confere_tam 2.16.76.1.3.5     "$DADOS_TITULO" 19
confere_tam 2.16.76.1.4.2.1.1 "$DADOS_AC"      9

# OCTET STRING, não UTF8String: é o que o DOC-ICP-04 define para este campo, e é
# o que os certificados e-CPF reais trazem. Testar contra o tipo errado ensinaria
# um parser errado.
#
# E o valor vai em HEX porque o parser do openssl.cnf faz TRIM do espaço em
# branco no fim do valor — e o campo termina justamente com o preenchimento do
# órgão expedidor ("SSPSP "). Escrito como texto, saía com 50 bytes em vez de 51,
# e um parser que confere o tamanho fixo rejeitaria.
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
HEX_PF="$(hex "$DADOS_PF")"
HEX_CEI="$(hex "$DADOS_CEI")"
HEX_TITULO="$(hex "$DADOS_TITULO")"
HEX_AC="$(hex "$DADOS_AC")"

cat > "$TMP/titular.cnf" <<EOF
[titular]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = @alt
certificatePolicies = @politica
crlDistributionPoints = URI:http://ac-teste.invalid/ac-teste.crl

[alt]
otherName.0 = 2.16.76.1.3.1;FORMAT:HEX,OCTETSTRING:${HEX_PF}
otherName.1 = 2.16.76.1.3.6;FORMAT:HEX,OCTETSTRING:${HEX_CEI}
otherName.2 = 2.16.76.1.3.5;FORMAT:HEX,OCTETSTRING:${HEX_TITULO}
email = teste@remoteid.local
otherName.3 = 2.16.76.1.4.2.1.1;FORMAT:HEX,OCTETSTRING:${HEX_AC}

# OID de política INVENTADO (2.16.76.1.2.900.x não é de ninguém) e domínio
# .invalid: nada aqui pode ser confundido com uma política real da ICP-Brasil.
[politica]
policyIdentifier = 2.16.76.1.2.900.1
CPS.1 = http://ac-teste.invalid/dpc.pdf
EOF

cat > "$TMP/ac.cnf" <<'EOF'
[ac]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

echo "→ AC sintética"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SAIDA/fake-ca-key.pem"
openssl req -x509 -new -utf8 -key "$SAIDA/fake-ca-key.pem" -sha256 -days 7300 \
    -subj "$DN_AC" -extensions ac -config "$TMP/ac.cnf" -out "$SAIDA/fake-ca-cert.pem"

echo "→ certificado do titular, emitido pela AC"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SAIDA/fake-key.pem"
openssl req -new -utf8 -key "$SAIDA/fake-key.pem" -subj "$DN_TITULAR" -out "$TMP/titular.csr"
# Serial de 16 bytes: é o tamanho que a Certisign emite. O `-CAcreateserial` do
# openssl gera 20, e o keyName ficaria com 40 hex em vez de 32.
SERIAL_HEX="$(openssl rand -hex 16)"
openssl x509 -req -in "$TMP/titular.csr" -CA "$SAIDA/fake-ca-cert.pem" -CAkey "$SAIDA/fake-ca-key.pem" \
    -set_serial "0x$SERIAL_HEX" -sha256 -days 3650 \
    -extfile "$TMP/titular.cnf" -extensions titular -out "$SAIDA/fake-cert.pem"
openssl x509 -in "$SAIDA/fake-cert.pem" -outform DER -out "$SAIDA/fake-cert.der"
rm -f "$SAIDA/fake-ca-cert.srl"

echo "→ conferindo o que saiu"
falhar() { echo "  ✗ $*" >&2; exit 1; }
espera() { # espera <descrição> <padrão>
  openssl x509 -in "$SAIDA/fake-cert.pem" -noout -text | grep -q "$2" \
    && echo "  ✓ $1" || falhar "$1 (padrão ausente: $2)"
}
espera "CA:FALSE (é folha, não autoridade)"        "CA:FALSE"
espera "keyUsage com Digital Signature"            "Digital Signature"
espera "keyUsage com Non Repudiation"              "Non Repudiation"
espera "keyUsage com Key Encipherment"             "Key Encipherment"
espera "certificatePolicies"                        "Certificate Policies"
espera "crlDistributionPoints"                      "CRL Distribution Points"
espera "subjectAltName com otherName da ICP-Brasil" "othername"

# O tamanho do campo é fixo em 45: foi assim que o trim do openssl.cnf apareceu.
# `04 2d` é OCTET STRING de 0x2d = 45 bytes.
DUMP="$(openssl asn1parse -in "$SAIDA/fake-cert.pem" | grep -A0 "OCTET STRING" | tr -d ' ' | tr 'A-F' 'a-f')"
if printf '%s' "$DUMP" | grep -q "042d${HEX_PF}"; then
  echo "  ✓ campo PF com os 45 bytes exatos (sem trim)"
else
  falhar "o campo 2.16.76.1.3.1 não tem 51 bytes — o openssl comeu o preenchimento?"
fi

# A cadeia tem de fechar: certificado do titular assinado pela AC.
openssl verify -CAfile "$SAIDA/fake-ca-cert.pem" "$SAIDA/fake-cert.pem" >/dev/null \
  && echo "  ✓ a cadeia fecha contra a AC sintética" || falhar "a cadeia NÃO fecha"

# Autoassinado seria o bug de antes voltando.
SUBJ="$(openssl x509 -in "$SAIDA/fake-cert.pem" -noout -subject)"
ISSU="$(openssl x509 -in "$SAIDA/fake-cert.pem" -noout -issuer)"
[ "${SUBJ#subject=}" != "${ISSU#issuer=}" ] || falhar "voltou a ser autoassinado"
echo "  ✓ emissor é a AC, não o próprio titular"

N_OU="$(openssl x509 -in "$SAIDA/fake-cert.pem" -noout -subject | tr ',' '\n' | grep -c 'OU=')"
[ "$N_OU" -eq 5 ] && echo "  ✓ subject com 5 OUs, como o certificado real" \
                  || falhar "subject tem $N_OU OUs, esperado 5"

N_SER="$(openssl x509 -in "$SAIDA/fake-cert.pem" -noout -serial | cut -d= -f2 | wc -c)"
[ "$((N_SER - 1))" -eq 32 ] && echo "  ✓ serial de 16 bytes (32 hex), como o real" \
                            || falhar "serial com $((N_SER - 1)) hex, esperado 32"

for oid in 2.16.76.1.3.1 2.16.76.1.3.6 2.16.76.1.3.5 2.16.76.1.4.2.1.1; do
  openssl x509 -in "$SAIDA/fake-cert.pem" -noout -text | grep -q "$oid" \
    && echo "  ✓ otherName $oid presente" || falhar "otherName $oid ausente"
done

echo
echo "serial do titular: $(openssl x509 -in "$SAIDA/fake-cert.pem" -noout -serial | cut -d= -f2)"
echo "O mock lê serial e emissor do próprio DER; não há constante para atualizar."
