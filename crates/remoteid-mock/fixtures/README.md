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
