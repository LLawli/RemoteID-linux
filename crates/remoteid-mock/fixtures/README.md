# Fixtures do servidor mock — SINTÉTICAS, só teste

Estes arquivos são **falsos**. Não certificam ninguém, não valem nada, e vazá-los
não tem consequência: a chave não protege nenhum dado real, a AC é inventada e
não encadeia na raiz da ICP-Brasil, e o titular não existe.

- `fake-ca-key.pem` / `fake-ca-cert.pem` — a **AC de teste**
  (`CN=AC TESTE DESKTOPID`). Emite o certificado do titular.
- `fake-key.pem` — chave RSA-2048 sintética do titular. Existe para o mock
  assinar o digest do `requestHash` como o HSM faria, para a assinatura
  verificar contra o `fake-cert`.
- `fake-cert.pem` / `fake-cert.der` — o certificado do **titular**. O `.der` é
  embutido no binário do mock (`include_bytes!`).

## Por que não é mais autoassinado

Até 04/09/2026 o `fake-cert` era uma **CA autoassinada** (`CA:TRUE`), sem
`keyUsage` e sem `subjectAltName`. Um e-CPF da ICP-Brasil não se parece nada
com isso, e testar contra um certificado que não tem a forma do real esconde
justamente os bugs de parsing que aparecem em produção. Pior: o mock anunciava
na carteira um emissor (`AC TESTE DESKTOPID`) que o próprio DER contradizia,
porque o certificado era assinado pelo titular.

A forma atual copia a **estrutura** de um certificado real (medida num run do
harness; nenhum valor real foi copiado):

| característica | valor |
|---|---|
| `basicConstraints` | `CA:FALSE`, crítica |
| `keyUsage` | `digitalSignature, nonRepudiation, keyEncipherment`, crítica |
| `extendedKeyUsage` | `clientAuth, emailProtection` |
| `subjectAltName` | `otherName` 2.16.76.1.3.1 (45 bytes), 2.16.76.1.3.6 (12), 2.16.76.1.3.5 (19), 2.16.76.1.4.2.1.1 (9), mais o e-mail |
| OUs no subject | **cinco**, como no real |
| serial | 16 bytes (32 hex) |
| emissor | a AC de teste, com `OU` |

Duas armadilhas que essa fidelidade custou a descobrir:

1. O campo 2.16.76.1.3.1 tem **45 bytes**, não 51: é
   nascimento(8) + CPF(11) + NIS(11) + RG(15). O órgão expedidor **não** entra
   nele.
2. O conteúdo é **OCTET STRING**, não `UTF8String` — é por isso que o
   `openssl x509 -text` mostra `<unsupported>` nesses campos, tanto no real
   quanto aqui.

## Identidade

`CN=JOÃO GONÇALVES DE ASSUNÇÃO:11111111111`. Fictícia de propósito, e com
acento e cedilha de propósito: um nome em ASCII puro não exercitaria o
`UTF8String` no DN. O CPF `111.111.111-11` é sequência repetida, rejeitada por
qualquer validação — fixture não pode carregar CPF que passe na regra da
Receita, porque alguém poderia tomar por real.

## Regerar

```sh
tools/gerar-fixtures-mock.sh
```

O script confere o que gerou (CA:FALSE, os dois keyUsage, os quatro otherName,
os 45 bytes exatos do campo PF, a cadeia fechando contra a AC, os 5 OUs e o
serial de 16 bytes) e falha se algo sair diferente.

**Não há constante para atualizar depois**: o mock lê o serial do próprio DER, e
`conferir_emissor` derruba o processo no boot se as fixtures forem regeradas com
outra AC.
