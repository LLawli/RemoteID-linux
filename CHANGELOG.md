# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e a numeração segue o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

O fluxo de release lê deste arquivo: ao empurrar uma tag `vX.Y.Z`, a seção
`[X.Y.Z]` daqui vira o corpo da release no GitHub. Uma tag sem a seção
correspondente faz o release falhar de propósito — release sem nota é release
que ninguém sabe o que mudou.

## [Não publicado]

Primeira versão em preparação. Quando ela sair, esta seção vira `[0.1.0]` com a
data, e o conteúdo abaixo passa a valer como as notas dessa release.

### Adicionado

- **Motor de assinatura** (`remoteid-core` e o domínio): dado um hash, PIN e
  OTP, devolve a assinatura RSA-2048 do certificado em nuvem, com paridade byte
  a byte com o app oficial de macOS — canonicalização do corpo, `Authorization`
  como assinatura dos bytes exatos enviados, e o tratamento de "HTTP 200 pode
  ser erro".
- **CLI `remoteid`**: `preparar`, `assinar` (arquivo, hash ou entrada padrão),
  `--pkcs7` para envelope CAdES-BES destacado, `diagnostico` e `harness`.
- **Módulo PKCS#11** (`libremoteid_pkcs11.so`): expõe o certificado em nuvem a
  qualquer consumidor de NSS ou PKCS#11 (Papers/poppler, Firefox, Chromium),
  com o `C_Sign` atendido pelo app por um socket UNIX.
- **App gráfico `remoteid-app`** (GTK4 + Libadwaita): janela de instalação,
  painel, seleção de certificado e configurações, mais o diálogo modal de
  PIN/OTP que autoriza as assinaturas pedidas pelo módulo PKCS#11.
- **Servidor RemoteID falso** (`remoteid-mock`) e o ambiente de teste isolado em
  `/tmp`, acionado por uma variável só (`TEST_URL`), que reloca app, CLI e
  módulo juntos sem tocar na conta real.
- **Gate de integração ponta a ponta** (`make teste-integracao`): exercita
  `pkcs11-tool` → módulo → socket → serviço → servidor falso, conferindo a
  assinatura contra a chave pública do certificado e a redação de PIN e OTP no
  diagnóstico.

### Segurança

- PIN, OTP e senha nunca são gravados em log, diagnóstico ou relatório. A forma
  canônica assinada, que contém PIN e OTP concatenados, aparece só como
  impressão digital SHA-256. A redação é regra de domínio, pura e testável, e é
  verificada pelo gate de integração.
- A chave privada da instalação não sai do cofre: a porta `CofreDeChave` expõe
  `assinar`, nunca a chave crua.
- Estado local e chave da instalação são gravados com permissão 0600, e o socket
  UNIX do app também.
- `cargo audit` roda no CI. A única exceção registrada é a RUSTSEC-2023-0071
  (Marvin Attack na crate `rsa`), que **não tem versão corrigida publicada**; o
  motivo pelo qual o risco não se aplica a este uso, e o gatilho para reabrir a
  decisão, estão em `.cargo/audit.toml`.
