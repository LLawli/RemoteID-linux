# Fixtures do servidor mock — SINTÉTICAS, só teste

Estes arquivos são **falsos**, gerados só para o teste local (`remoteid-mock`).
Não certificam ninguém, não valem nada, e vazá-los não tem consequência: a chave
não protege nenhum dado real.

- `fake-key.pem` — chave RSA-2048 **sintética**. NÃO é a chave de nenhuma
  instalação real. Existe para o mock assinar o digest do `requestHash` como o
  HSM faria, para a assinatura verificar contra o `fake-cert`.
- `fake-cert.pem` / `fake-cert.der` — o certificado do "titular", no estilo
  ICP-Brasil pessoa física (`CN=TESTE DESKTOPID:00000000000`), emitido pela AC
  falsa abaixo com a `fake-key.pem`. Declara no AIA o `caIssuers`
  `http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c`. O `.der` é
  embutido no binário do mock (`include_bytes!`).
- `fake-ac.pem` (`CN=AC TESTE DESKTOPID`) e `fake-ac-raiz.pem`
  (`CN=AC RAIZ TESTE DESKTOPID`) — a cadeia **sintética** (issue 22). As chaves
  delas não são versionadas: não servem para nada depois de assinar, e quem
  regerar gera outras.
- `AC_TESTE_DESKTOPID.p7c` — AC e raiz num PKCS#7 "certs-only", a mesma forma
  do `.p7c` que a Certisign publica. É o que o mock devolve no GET do
  `caIssuers`, e a fixture dos testes de `remoteid-cadeia`, `remoteid-pkcs11` e
  `remoteid-aplicacao`.

O AIA aponta para a porta padrão do mock. Em modo de teste (`TEST_URL`) o motor
troca a origem da URL pela do `TEST_URL`, então o gate, que sobe o mock numa
porta efêmera, baixa a cadeia do mock certo.

Regerar (se algum dia precisar). O `-not_before`/`-not_after` fixos mantêm a
validade que os testes conferem (31/08/2036), e pedem OpenSSL 3.4 ou mais novo:

```sh
cd crates/remoteid-mock/fixtures
T="$(mktemp -d)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/raiz.key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/ac.key"
openssl req -x509 -new -key "$T/raiz.key" -sha256 \
  -not_before 20260903191734Z -not_after 20460831191734Z \
  -subj "/C=BR/O=ICP-Brasil TESTE/CN=AC RAIZ TESTE DESKTOPID" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out fake-ac-raiz.pem
openssl req -new -key "$T/ac.key" \
  -subj "/C=BR/O=ICP-Brasil TESTE/CN=AC TESTE DESKTOPID" -out "$T/ac.csr"
printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid' >"$T/ac.ext"
openssl x509 -req -in "$T/ac.csr" -CA fake-ac-raiz.pem -CAkey "$T/raiz.key" -sha256 \
  -not_before 20260903191734Z -not_after 20410831191734Z -extfile "$T/ac.ext" -out fake-ac.pem
openssl req -new -key fake-key.pem \
  -subj "/C=BR/O=ICP-Brasil TESTE/OU=DesktopID TESTE/CN=TESTE DESKTOPID:00000000000" \
  -out "$T/cert.csr"
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'authorityInfoAccess=caIssuers;URI:http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c' \
  >"$T/cert.ext"
openssl x509 -req -in "$T/cert.csr" -CA fake-ac.pem -CAkey "$T/ac.key" -sha256 \
  -not_before 20260903191734Z -not_after 20360831191734Z -extfile "$T/cert.ext" -out fake-cert.pem
openssl x509 -in fake-cert.pem -outform DER -out fake-cert.der
openssl crl2pkcs7 -nocrl -certfile fake-ac.pem -certfile fake-ac-raiz.pem \
  -outform DER -out AC_TESTE_DESKTOPID.p7c
rm -rf "$T"
openssl verify -CAfile fake-ac-raiz.pem -untrusted fake-ac.pem fake-cert.pem
openssl x509 -in fake-cert.pem -noout -serial   # atualizar SERIAL no main.rs
```

Se regerar, atualize a constante `SERIAL` em `../src/main.rs` (o serial do cert
entra no `keyName` da carteira). A `fake-key.pem` fica a mesma: só regere ela
se quiser outro par, e aí o comando dela é
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out fake-key.pem`.

## Rodar contra uma carteira de verdade, sem versionar nada

Uma fixture sintética não tem a forma de um certificado da ICP-Brasil de
verdade: faltam as extensões `otherName` do titular, os vários OUs, os acentos
no DN. É exatamente aí que moram os bugs de parsing e os defeitos de tela, e é o
que este arquivo não pode reproduzir — um certificado real identifica uma pessoa
e **não entra no repositório**, nem redigido.

Por isso o mock aceita um diretório de fora:

```sh
REMOTEID_MOCK_FIXTURES=~/.local/share/remoteid-mock-local remoteid-mock
```

O diretório precisa de três arquivos:

| arquivo | o quê |
|---|---|
| `cert.der` | o certificado X.509 em DER, o que a carteira devolve em `base64` |
| `key.pem` | a chave RSA que **casa com esse certificado**, para o mock assinar o `requestHash` |
| `keyname.txt` | o `keyName` que o servidor devolveria, na forma `<serial>;<issuer>` |
| `cadeia.p7c` | opcional: o `.p7c` público do `caIssuers` do certificado. Sem ele, o GET do `caIssuers` recebe 404, que é o caminho do "repositório fora do ar" |

A chave privada de um certificado em nuvem vive no HSM e não sai de lá, então o
par local não é o do titular: o caminho é **reemitir** o certificado real
trocando só a chave pública (`openssl x509 -force_pubkey`, preservando subject,
serial, validade e extensões). O que se ganha é a forma e o conteúdo reais; o
que não se ganha, e não faz falta aqui, é a cadeia fechar contra a ICP-Brasil.

Com a variável posta e o diretório imprestável o mock **morre**, em vez de cair
de volta na fixture embutida: um teste verde exibindo outra identidade não prova
nada.
