# Fixtures do servidor mock — SINTÉTICAS, só teste

Estes arquivos são **falsos**, gerados só para o teste local (`remoteid-mock`).
Não certificam ninguém, não valem nada, e vazá-los não tem consequência: a chave
não protege nenhum dado real.

- `fake-key.pem` — chave RSA-2048 **sintética**. NÃO é a chave de nenhuma
  instalação real. Existe para o mock assinar o digest do `requestHash` como o
  HSM faria, para a assinatura verificar contra o `fake-cert`.
- `fake-cert.pem` / `fake-cert.der` — certificado X.509 **self-signed**, com um
  subject no estilo ICP-Brasil pessoa física (`CN=TESTE DESKTOPID:00000000000`).
  O `.der` é embutido no binário do mock (`include_bytes!`).

Regerar (se algum dia precisar):

```sh
cd crates/remoteid-mock/fixtures
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out fake-key.pem
openssl req -x509 -new -key fake-key.pem -days 3650 -sha256 \
  -subj "/C=BR/O=ICP-Brasil TESTE/OU=DesktopID TESTE/CN=TESTE DESKTOPID:00000000000" \
  -out fake-cert.pem
openssl x509 -in fake-cert.pem -outform DER -out fake-cert.der
openssl x509 -in fake-cert.pem -noout -serial   # atualizar SERIAL no main.rs
```

Se regerar, atualize a constante `SERIAL` em `../src/main.rs` (o serial do cert
entra no `keyName` da carteira).

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

A chave privada de um certificado em nuvem vive no HSM e não sai de lá, então o
par local não é o do titular: o caminho é **reemitir** o certificado real
trocando só a chave pública (`openssl x509 -force_pubkey`, preservando subject,
serial, validade e extensões). O que se ganha é a forma e o conteúdo reais; o
que não se ganha, e não faz falta aqui, é a cadeia fechar contra a ICP-Brasil.

Com a variável posta e o diretório imprestável o mock **morre**, em vez de cair
de volta na fixture embutida: um teste verde exibindo outra identidade não prova
nada.
