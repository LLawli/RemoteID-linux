# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e a numeração segue o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

O fluxo de release lê deste arquivo: ao empurrar uma tag `vX.Y.Z`, a seção
`[X.Y.Z]` daqui vira o corpo da release no GitHub. Uma tag sem a seção
correspondente faz o release falhar de propósito — release sem nota é release
que ninguém sabe o que mudou.

## [Não publicado]

### Corrigido

- **O diagnóstico não grava mais os dados pessoais do certificado** (issue
  #30). A cada assinatura o servidor devolve o certificado do titular já
  parseado, e o JSONL em `diag/` guardava nome, CPF, RG, e-mail, data de
  nascimento, título de eleitor e o resto em claro, inclusive no relato que
  vai para terceiros. Esses campos agora saem como `<redigido>`, mesmo com
  `REMOTEID_DIAG_RAW=1`. O serial do certificado (em qualquer das grafias do
  protocolo), a `cert_key` e a `signatureBase64` saem como impressão digital,
  o que ainda permite saber se duas linhas falam do mesmo certificado. Emissor
  e validade continuam legíveis, porque é com eles que se diagnostica
  certificado vencido ou de outra AC. Os arquivos de diagnóstico gravados
  antes desta versão continuam com os dados: apague-os de `diag/` se for
  enviá-los.

## [0.3.1] - 2026-10-02

### Corrigido

- **Fechar a janela não desliga mais o assinador** (issue #26). Fechada a
  última janela, o app terminava e apagava o socket; o certificado continuava
  aparecendo no PJeOffice e no navegador (quem o lista é o módulo), mas toda
  assinatura falhava com `CKR_DEVICE_ERROR`, sem nada no diag, e o
  "Reautorizar" não adiantava porque o problema era o app fechado. Agora fechar
  a janela só a esconde: o app segue no ar atendendo o socket e avisa isso
  numa notificação na primeira vez. Para encerrar, **Sair** no menu da janela
  (Ctrl+Q).

- **Abrir o app de novo não cria mais um segundo serviço** (issue #26). Com o
  app já aberto, uma nova abertura (pelo menu ou pela janela do Adv BR) montava
  outra janela com outro motor e refazia o socket para ele; as janelas antigas
  ficavam ligadas a um serviço que não atendia mais ninguém, e um "Reautorizar"
  numa delas não valia para a próxima assinatura. Agora a segunda abertura só
  traz de volta a janela que já existe.

- **Pedido de assinatura sem o app no ar deixa rastro** (issue #26). O módulo
  passa a registrar em `modulo-pkcs11.jsonl`, no diretório do diag, quando não
  acha o app (`assinatura.sem_app`) ou quando o app aceita o pedido e não
  responde (`assinatura.sem_resposta`), com o socket procurado e o programa que
  pediu. Antes essa falha não aparecia em lugar nenhum e parecia problema de
  protocolo.

## [0.3.0] - 2026-09-29

### Corrigido

- **O token passa a publicar a cadeia de autoridades, e o assinador do
  Projudi (TJPR) deixa de enviar a assinatura sem ela** (issue #22). O token
  expunha só o certificado final, o SunPKCS11 devolvia uma cadeia de tamanho 1,
  e o assinador do TJPR caía num caminho de completar a cadeia que está
  quebrado do lado dele; o servidor recusava com "Trust anchor for
  certification path not found". Agora o app baixa as ACs do `caIssuers` do
  próprio certificado (o `.p7c` da Certisign, que traz a cadeia até a raiz),
  guarda no `state.json` e o módulo as publica como `CKO_CERTIFICATE` de
  autoridade, ao lado do certificado do titular, sem parear com a chave. O
  download acontece no preparo e, para instalações que já existiam, na
  primeira vez que o app abre depois da atualização; o módulo continua sem ir
  à rede. Se o download falhar, o token segue como antes e o motivo vai ao
  diag. Com a cadeia no token, o `findCertificate` do assinador do TJPR
  continua vendo um certificado só e escolhendo sozinho.

- **PIN recusado pelo servidor não volta mais preenchido, e a recusa aparece
  para o titular** (issue #21). O diálogo guardava o PIN no cache antes de o
  `tokensessao` aceitá-lo, então um PIN errado voltava preenchido (com o foco
  já no OTP) em cada assinatura dos 5 minutos seguintes, e cada reenvio podia
  contar para o bloqueio do certificado. Agora o PIN só entra no cache depois
  de aceito, e uma recusa limpa o cache. Na recusa de PIN ou OTP, o diálogo
  reabre dentro da mesma assinatura com a mensagem do servidor e o PIN vazio,
  até 3 tentativas; esgotadas, o módulo responde `CKR_PIN_INCORRECT` em vez de
  `CKR_FUNCTION_FAILED`, que o PJeOffice mostrava como stack trace. A
  mensagem "PIN ou e-Token incorreto" ganhou dica própria no diag: antes ela
  caía na do "e-token", que afirmava, errado, que o PIN tinha sido aceito.

### Segurança

- **rustls 0.23.45, que corrige o RUSTSEC-2026-0285** (#20). A versão anterior
  aceitava mensagens de handshake TLS 1.3 enviadas no nível de criptografia
  errado, quando vinham no mesmo registro de uma mensagem que troca a chave. O
  transcript continua autenticado, então não dá para alterar um handshake por
  aí; o efeito é aceitar em texto claro mensagens que deveriam vir cifradas. O
  rustls entra pelo ureq, no transporte até o servidor RemoteID.

## [0.2.0] - 2026-09-08

### Adicionado

- **O módulo PKCS#11 anuncia `CKF_ENCRYPT` em `CKM_RSA_PKCS` e cifra com a
  chave pública** (issue #10). O PJeOffice não autenticava no Linux: o
  signer4j precisa de RSA cru pela JCA, e a única porta é o
  `Cipher.RSA/ECB/PKCS1Padding` do SunPKCS11, que desde o JDK-8176837 só é
  registrado se o mecanismo anunciar `CKF_ENCRYPT`. Com a chave privada em
  `ENCRYPT_MODE` o Java faz `C_SignInit` + `C_Sign`, que já existiam; o que
  faltava era o anúncio. `C_EncryptInit`/`C_Encrypt` passam a existir de
  verdade, só com a chave pública (a privada recebe
  `CKR_KEY_FUNCTION_NOT_PERMITTED`), sem socket e sem PIN. É uma divergência
  deliberada do módulo oficial, que é sign-only. A prova em Java
  (`tools/prova-jca-pkcs11/ProvaCipher.java`) entra no gate de integração.
- **Modo cru no caminho de produção** (issue #11). A sondagem ao vivo de
  05/09/2026 provou que o `requestHashSessionSignature` com `algorithm: ""`
  só aplica o padding PKCS#1 v1.5 ao bloco enviado. O `CKM_RSA_PKCS` do
  módulo passa a mandar o bloco inteiro nesse modo, seja qual for o hash
  dentro dele; o verbo `sign` do socket ganha o campo `algoritmo` (opcional,
  padrão `SHA256`); o motor e o daemon recebem um `Algoritmo` tipado, com a
  regra de tamanho num lugar só. É o que faz o `DigestInfo(MD5)` do
  `PjeAuthenticatorTask` chegar assinado ao PJeOffice. O mock imita o
  servidor medido, inclusive a forma exata da recusa.
- **O diag registra quem pediu cada assinatura.** Evento `assinatura.pedido`
  com `hospedeiro` (o `comm` do processo que chamou o `C_Sign`: `papers`,
  `firefox`, `java`), `algoritmo` e `bloco_bytes`. É a linha que responde,
  num relatório de bug, qual app disparou a assinatura.

### Alterado

- **`CKM_RSA_PKCS` deixa de reconhecer DigestInfo.** Antes, em produção, o
  módulo desmontava um DigestInfo(SHA-256) de 51 bytes para mandar só o hash,
  aceitava 32 bytes crus como se fossem o hash (e o servidor os embrulhava em
  DigestInfo), e recusava qualquer outro tamanho com `CKR_DATA_LEN_RANGE`.
  Agora o bloco vai como está, de 1 a 245 bytes, e recebe só o padding, que é
  o que a especificação define e o módulo oficial faz. Quem quer DigestInfo
  manda DigestInfo (poppler, NSS, OpenSSL e o SunPKCS11 já mandam); a
  assinatura desses continua byte a byte a mesma.

### Corrigido

- `C_SignInit` com sessão inexistente devolve `CKR_SESSION_HANDLE_INVALID`,
  e não um pânico convertido em `CKR_GENERAL_ERROR`.

### Interno

- **O `remoteid-mock` aceita uma carteira de fora**, por
  `REMOTEID_MOCK_FIXTURES=<dir>` (`cert.der`, `key.pem`, `keyname.txt`). Serve
  para rodar contra um certificado com a forma e o conteúdo de um real, que a
  fixture sintética não reproduz (as extensões `otherName` da ICP-Brasil, os
  vários OUs, os acentos no DN) e que não pode ser versionado, porque
  identifica uma pessoa. Sem a variável nada muda; com ela apontando para um
  diretório imprestável o mock morre, em vez de cair de volta na fixture
  embutida e exibir outra identidade.
- **Testes de mutação** (`cargo mutants`, 327 mutantes em 8 crates) fecharam os
  buracos que importavam: o guarda do retry silencioso com cache válido (um bug
  ali gastaria um OTP por recusa), o braço `CKM_SHA256_RSA_PKCS` de
  `preparar_bloco`, os handles de sessão do módulo, e o cliente do socket, que
  só o gate ponta a ponta exercita.
- **O passo da cifra no gate de integração exige OpenSC 0.26+** e é pulado onde
  a ferramenta é mais velha. O `pkcs11-tool` do Ubuntu 24.04 (0.25) procura uma
  chave secreta e falha antes de chamar o módulo, o que deixava o CI vermelho
  por causa da ferramenta. A cobertura fica com o `-M`, com a prova em Java e
  com os testes de ABI.


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
