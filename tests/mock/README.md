# Fixtures do servidor falso: sintéticas, só para teste

Vêm do `remoteid-mock` do RemoteID-linux v0.3.2. Não certificam ninguém e não
protegem nada real.

- `fake-key.pem`: a chave RSA-2048 do "titular". O servidor falso assina com
  ela o que o HSM assinaria, para a assinatura conferir com o `fake-cert`.
- `fake-cert.pem` e `fake-cert.der`: o certificado do titular
  (`CN=TESTE DESKTOPID:00000000000`), emitido pela AC falsa, válido até
  31/08/2036, com o `caIssuers`
  `http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c` no AIA. Serial
  `16C3F7EFA6CCE55817FA659DC8EAA29B7E512621`.
- `fake-ac.pem` (`CN=AC TESTE DESKTOPID`) e `fake-ac-raiz.pem`
  (`CN=AC RAIZ TESTE DESKTOPID`): a cadeia. As chaves delas não existem mais.
- `AC_TESTE_DESKTOPID.p7c`: AC e raiz num PKCS#7 certs-only, a forma do `.p7c`
  que a Certisign publica. É o que o servidor falso devolve no GET do
  `caIssuers`.

Para regerar, o roteiro com `openssl` está no README das fixtures do
RemoteID-linux v0.3.2 (`crates/remoteid-mock/fixtures/README.md`). Se o
certificado mudar, atualize o `SERIAL` de `src/bin/remoteid-mock.rs`.
