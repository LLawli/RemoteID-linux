# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e a numeração segue o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

O fluxo de release lê deste arquivo: ao empurrar uma tag `vX.Y.Z`, a seção
`[X.Y.Z]` daqui vira o corpo da release no GitHub. Uma tag sem a seção
correspondente faz o release falhar de propósito — release sem nota é release
que ninguém sabe o que mudou.

## [Não publicado]

## [0.1.2] - 2026-09-04

### Corrigido

- **Assinatura em fluxo no módulo PKCS#11** (issue #7). `C_SignUpdate` e
  `C_SignFinal` não eram implementados, e quem assina em fluxo nunca chama
  `C_Sign`: o BouncyCastle escreve o documento num
  `SignatureUpdatingOutputStream`, que vira `C_SignInit` → `C_SignUpdate`(n) →
  `C_SignFinal`. Na prática, o **PJeOffice** recebia
  `CKR_FUNCTION_NOT_SUPPORTED` no primeiro `update` e não conseguia assinar.

  `C_SignUpdate` agora acumula os pedaços na sessão e `C_SignFinal` assina o
  acumulado, pelo mesmo caminho de assinatura do `C_Sign` — a assinatura sai
  idêntica para o mesmo conteúdo. Sem `C_SignInit` antes, ambos devolvem
  `CKR_OPERATION_NOT_INITIALIZED`; depois do `C_SignFinal` a operação termina,
  dê certo ou não.

### Interno

- `make check` passou a espelhar o job do CI (`cargo fmt --all --check`, testes,
  clippy com `-D warnings` e build de release). Antes o alvo local aprovava o
  que o CI reprovava, e a divergência apareceu num pull request.

## [0.1.1] - 2026-09-04

Torna o projeto instalável como aplicativo de verdade: ele agora tem ícone,
aparece no menu e sai do tarball com um instalador, em vez de exigir que cada
pessoa espalhe arquivos à mão.

### Adicionado

- **Ícone do aplicativo**, colorido e symbolic (`dev.lukakuuhaku.RemoteID`).
  Nuvem porque a chave do certificado mora no HSM da Certisign e não na máquina;
  selo dentado porque é certificação. O symbolic é um desenho próprio, não uma
  redução: a 16px o selo vira borrão, então lá a nuvem é sólida e o check é
  vazado nela.
- **Lançador `.desktop`**, com `StartupWMClass` casando o application id — é o
  que evita o compositor mostrar dois ícones na barra.
- **`instalar.sh` e `desinstalar.sh`**, também expostos como `make instalar` e
  `make desinstalar`. Instalam em `~/.local` sem root, registram o módulo no
  p11-kit e atualizam os caches de ícone e de lançador. O desinstalador
  **preserva** o estado da conta em `~/.local/state/remoteid`: apagá-lo exigiria
  novo login e registro.
- O pacote da release passa a incluir o **aplicativo gráfico** (`remoteid-app`),
  o ícone, o lançador e o instalador. Antes trazia só a CLI e o módulo, e um
  `.desktop` ali dentro apontaria para um binário inexistente.

### Modificado

- O `remoteid-app` distribuído no tarball exige **GTK4 e Libadwaita** instalados
  na máquina. A CLI (`remoteid`) e o módulo PKCS#11 continuam sem depender de
  nada além do sistema base.

## [0.1.0] - 2026-09-04

Primeira versão pública. O protocolo do certificado em nuvem RemoteID foi
reconstruído por engenharia reversa do aplicativo oficial de macOS e confirmado
ao vivo: assinar pelo caminho **PIN + OTP** funciona ponta a ponta, com a
assinatura devolvida pelo HSM verificada contra a chave pública do certificado
do titular. O caminho **push** (aprovar no celular) está implementado com
paridade byte a byte com o app oficial, mas **nunca foi exercitado com uma conta
real** — é hipótese até que alguém prove o contrário.

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
