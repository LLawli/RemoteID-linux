# Escopo da migração DesktopID-linux → RemoteID-linux

Documento de partida. Levanta o estado atual, a arquitetura-alvo (núcleo
funcional + portas/adaptadores), a decomposição em crates, os contratos a
extrair, um plano faseado e as decisões ainda em aberto. Nada aqui é código
final; é o mapa que as fases seguintes vão seguir.

## 1. Objetivo

Reconstruir o app (hoje em `~/Personal/DesktopID-linux`) com isolamento real
entre módulos e domínios explícitos, sob um paradigma inspirado no funcional:

- **Núcleo funcional puro**: funções que recebem valor e devolvem valor, sem
  I/O dentro delas, testáveis isoladamente.
- **Bordas imperativas**: crates que cuidam de I/O (disco, rede, relógio,
  ambiente, UI, FFI).
- **Contratos (traits/portas)** entre os dois, para trocar implementação sem
  tocar no núcleo. Casos-alvo do usuário:
  - Estado da conta hoje em `state.json`, trocável por XML ou Postgres só
    implementando o contrato do repositório de estado.
  - Chave RSA da instalação hoje em `installation-key.pem`, trocável por
    Postgres/HSM só implementando o contrato do cofre de chave.
  - Uma futura versão "central", que serve várias contas e guarda conta +
    certificados em Postgres, cai fora só reimplementando essas duas portas.

O padrão é **Functional Core, Imperative Shell** combinado com **Portas e
Adaptadores (hexagonal)**.

## 2. Restrição dura: o que NÃO pode mudar

O usuário controla tudo **exceto o protocolo de comunicação com o servidor
RemoteID** (Certisign). Esse protocolo foi reconstruído por engenharia reversa
e confirmado ao vivo; é a única parte que precisa de paridade byte a byte:

- Corpos das requisições (`protocol.rs`), endpoints (`config.rs`).
- Canonicalização e a assinatura do `Bearer` (`canonical.rs` + `crypto`):
  a assinatura cobre **os bytes exatos** do corpo serializado. Reserializar em
  qualquer ponto quebra a assinatura (ver a nota em `http.rs`).
- Formato opaco do `sessionToken` e a regra "HTTP 200 pode ser erro".

Tudo o mais é reescrevível à vontade: o protocolo do socket interno
(app ↔ módulo PKCS#11), o CLI, os formatos de armazenamento, as traits, os
nomes de crate e de variáveis de ambiente.

> Consequência de projeto: o "protocolo do servidor" vira um domínio puro e
> **fechado**, tratado como especificação congelada com testes de ouro. O
> protocolo do socket vira um domínio puro **aberto**, livre para evoluir.

## 3. Diagnóstico do estado atual

Workspace com 7 crates, ~10,7k linhas de Rust. A qualidade é alta (comentários
explicando o porquê, testes densos, invariantes de segurança). O problema
não é dívida técnica: é que **`desktopid-core` mistura puro e impuro** no mesmo
crate, então o isolamento pedido não existe ainda.

Classificação de cada módulo do core hoje:

| Módulo | Natureza | Destino |
|---|---|---|
| `canonical.rs` | puro | domínio: protocolo-servidor |
| `protocol.rs` | puro | domínio: protocolo-servidor |
| `config.rs` (constantes + `classificar`) | puro | domínio: protocolo-servidor |
| `authmode.rs` | puro | domínio: autorização |
| `pkcs7.rs` | puro | domínio: assinatura/CAdES |
| `error.rs` | puro | domínio: tipos compartilhados |
| `state.rs` tipos + política de cache (`Certificado`, `SessaoCache`, `epoch_do_token`, `vale_a_pena_tentar`) | puro | domínio: estado/sessão |
| `crypto.rs` transformações (`sha256`, `b64`, `assinar_digest` dado o par, `verificar_com_certificado`) | puro | domínio: cripto |
| `crypto.rs` `ChaveInstalacao::carregar_ou_gerar/carregar` | **I/O** (disco, RNG) | adaptador: cofre PEM |
| `state.rs` `Estado::carregar/salvar`, `dir_dados`, `dir_diag` | **I/O** (disco, env, XDG) | adaptador: store JSON + porta ambiente |
| `http.rs` | **I/O** (rede, ureq) | adaptador: transporte HTTP |
| `diag.rs` (escrita) | **I/O** (disco); redação é pura | porta diagnóstico (sink) + redação no núcleo |
| `engine.rs` | orquestração + I/O direto (`/proc`, `env`, HTTP, disco) | crate de aplicação (shell) |

Sementes boas que já existem e devem ser preservadas/generalizadas:

- **`Prompter`** (trait em `desktopid-daemon`) já é uma porta bem-feita para
  PIN/OTP. Vira o modelo dos outros contratos.
- **`desktopid-protocolo`** já é crate-folha sem GTK, o que mantém o `cdylib`
  do PKCS#11 livre de GTK. Esse constraint do grafo de dependências continua.
- **Política de cache do `sessionToken`** já é função pura testada.
- **`desktopid-mock`** + modo `TEST_URL` já provam o fluxo ponta a ponta sem
  tocar a produção: é o embrião do adaptador de transporte de teste.
- **`assinar_com_cache(digest, obter_fatores)`**: o closure isola a parte
  interativa; é exatamente a forma que o núcleo puro precisa (a decisão sobe,
  o efeito desce).
- **Corpus de runs reais em `.logs/`** (19 relatórios do harness do testador):
  transcript HTTP completo de cada endpoint, com a maioria das runs falhando em
  algum ponto. É a fonte para os testes de ouro do protocolo fechado e para a
  tabela de classificação de erros (ver §10).

## 4. Os contratos a extrair (as portas)

Este é o coração da migração. Cada porta é uma trait definida junto ao núcleo e
implementada por um ou mais adaptadores na borda.

| Porta | Responsabilidade | Adaptador padrão | Adaptadores futuros |
|---|---|---|---|
| `RepositorioEstado` | carregar/salvar o `Estado` (conta: userId, codigoDesktop, certificados, auth_mode, cache de sessões) | `json` (`state.json`, 0600, escrita atômica) | `xml`, `postgres` (central) |
| `CofreDeChave` | dar a chave pública em PEM para o registro e **assinar** um digest (a chave crua fica dentro do adaptador) | `pem` (`installation-key.pem`, 0600) | `postgres`, HSM |
| `TransporteRemoteId` | enviar a requisição já assinada ao servidor e devolver corpo+status | `ureq` | mock (teste), reqwest/async |
| `Diagnostico` | receber eventos já redigidos e persistir | `jsonl` (arquivo por execução, poda) | nulo, syslog |
| `Prompter` | obter PIN+OTP do usuário (já existe) | `gtk` | fixos (teste) |
| `Relogio` | tempo atual em epoch | relógio do sistema | fixo (teste) |
| `Ambiente` | hostname (`dominioRede`), usuário (`USER`), diretórios, env | real | fake (teste) |

Dois pontos de projeto que valem agora, não depois:

1. **A chave nunca precisa sair do cofre.** `CofreDeChave` expõe `assinar`, não
   `chave_privada`. Isso é o que deixa um adaptador Postgres/HSM viável sem
   vazar material sensível para o núcleo.

2. **As portas de estado e chave devem ser endereçadas por identidade de
   instalação/conta**, não assumir uma instalação global única. Ex.:
   `RepositorioEstado::carregar(&self, id: &IdInstalacao)`. No desktop o `id` é
   um singleton implícito; na versão central é a chave da conta no Postgres.
   Desenhar assim agora evita uma mudança quebradora quando a versão central
   chegar (é literalmente o objetivo declarado do usuário).

A **redação de segredos** (nunca logar PIN/OTP, tokens viram impressão digital)
é regra de domínio: fica no núcleo, pura. O `Diagnostico` só persiste o que já
foi redigido. Assim a garantia de segurança é testável sem tocar disco.

## 5. Arquitetura-alvo de crates

Grafo de dependências (as setas apontam para a dependência; o núcleo não conhece
ninguém da borda):

```
        delivery/borda de entrada
  cli    app(gtk)    pkcs11(cdylib)    mock
    \       |            |             /
     \      v            v            /
        remoteid-aplicacao  ......  remoteid-protocolo (socket, folha)
              |   (orquestra as portas)
              v
        remoteid-portas (as traits)
              ^
     .........|..............
     |        |             |
  store-json chave-pem   http   diag-jsonl   (adaptadores de I/O)
     |        |             |        |
     +--------+-------------+--------+---> remoteid-nucleo (domínios puros)
```

### 5.1 Núcleo funcional (puro, sem I/O)

Domínios explícitos. A granularidade é uma decisão (ver §8); a proposta é um
crate por domínio para o isolamento máximo que o usuário pediu:

- `remoteid-tipos`: `Error`, `Origem`, `Result`, ids (`IdInstalacao`) e tipos
  base compartilhados.
- `remoteid-protocolo-servidor` (**fechado**): payloads, endpoints,
  canonicalização, `classificar`, formato do `sessionToken`. O contrato
  imutável do §2, com testes de ouro contra respostas reais gravadas.
- `remoteid-cripto`: `sha256`, base64, assinatura/verificação RSA PKCS#1 v1.5
  como funções puras sobre material de chave passado por valor.
- `remoteid-autorizacao`: `Modo`, `Fatores`, a regra pin+otp vs push.
- `remoteid-assinatura` (CAdES/PKCS#7): montagem do envelope, pura.
- `remoteid-estado`: `Estado`, `Certificado`, `SessaoCache` e a política de
  cache/decisão do fluxo otimista (o que hoje está espalhado no `engine`).

### 5.2 Portas

- `remoteid-portas`: só as traits do §4 (mais os DTOs que elas trocam).
  Depende apenas de `remoteid-tipos` (+ serde). É o que os adaptadores
  implementam e a aplicação consome.

### 5.3 Adaptadores (borda de I/O)

- `remoteid-store-json`, `remoteid-chave-pem`, `remoteid-http` (ureq),
  `remoteid-diag-jsonl`.
- Futuros: `remoteid-store-xml`, `remoteid-store-postgres`,
  `remoteid-chave-postgres`.
- Cada um depende de `remoteid-portas` + a lib de I/O específica. Nenhum é
  dependência do núcleo.

### 5.4 Aplicação (imperative shell)

- `remoteid-aplicacao`: a orquestração do fluxo (login → registrar → carteira →
  tokensessao → requestHash → assinar com cache), genérica sobre as portas. É o
  destino do `engine.rs` menos as decisões puras (que descem ao núcleo) e menos
  o I/O direto (que desce às portas). O `Servico` do daemon atual (tratar
  `Requisicao` → `Resposta`) também mora aqui ou logo acima.

### 5.5 Delivery (borda de entrada)

- `remoteid-cli`, `remoteid-app` (GTK unificado + servidor do socket),
  `remoteid-pkcs11` (cdylib), `remoteid-protocolo` (socket, folha, livre para
  redesenho), `remoteid-mock` (servidor falso para o `teste-local`).
- Constraint mantido: `remoteid-pkcs11` é `cdylib` e **não pode linkar GTK**;
  fala com o app só via `remoteid-protocolo`.

## 6. Refatoração do motor (o passo mais delicado)

`engine::Motor` hoje é dono de `Estado`, `ChaveInstalacao`, `Http` e `Diag`, e
lê `/proc`, `env` e o relógio direto. Alvo:

1. Extrair as **decisões puras** para o núcleo: montar corpo do próximo passo,
   decidir se o cache vale, classificar a resposta, decidir reemitir. Entram
   valor (estado + resposta anterior + relógio) e saem valor (próxima ação).
2. Deixar na **aplicação** só a costura: chamar a porta certa, passar o
   resultado de volta ao núcleo, persistir via `RepositorioEstado`.
3. `Motor` passa a ser **genérico sobre as portas** (ou guarda `Box<dyn Porta>`).
   O mesmo fluxo roda com `json + pem + ureq` (desktop) ou
   `postgres + postgres + ureq` (central) sem reescrever a lógica.

Ganho concreto: hoje testar o fluxo exige subir um servidor HTTP mock e mexer
em `/tmp`. Depois, a maior parte é testável com valores em memória (portas
fake), e o teste de integração fica só para provar a costura.

## 7. Plano faseado

Cada fase termina na porta de validação do projeto:
`cargo test && cargo clippy --all-targets && cargo build --release` (o `make
check` atual). Nenhuma fase muda comportamento observável até a fase 5.

- **Fase 0 — esqueleto. [CONCLUÍDA]** Clonado para `RemoteID-linux`, workspace
  renomeado `desktopid-*` → `remoteid-*` (crates, binários, `REMOTEID_*`,
  diretórios), **sem compat**. Protocolo do servidor preservado byte a byte
  (URL `/api/manager/desktopid/`, `USER_AGENT`, campos). Porta de validação
  verde.
- **Fase 1 — extrair o núcleo puro. [CONCLUÍDA]** Seis crates de domínio, um por
  domínio, um commit cada: `remoteid-tipos`, `remoteid-cripto`,
  `remoteid-autorizacao`, `remoteid-estado`, `remoteid-assinatura`,
  `remoteid-protocolo-servidor`. Todos puros (sem `ureq`, `std::fs`, `std::env`).
  O I/O que estava misturado (chave PEM, `state.json`, dirs XDG) virou fachada no
  core (`crate::chave`, `crate::estado_fs`), semente dos adaptadores da Fase 2. O
  core re-exporta os domínios com os nomes antigos para a borda não mudar ainda.
  `remoteid-core` ficou só com a casca imperativa: `engine`, `http`, `diag`.
  Grafo de domínios sem ciclos; 104 testes verdes.
  - **Pendente da Fase 1 (levar para a Fase 2):** deduplicar o nome do app e os
    caminhos de diretório ainda hardcoded no GTK; isso casa com a introdução da
    porta `Ambiente`/config. O endereço do servidor já é fonte única.
- **Fase 2 — definir as portas e os adaptadores padrão. [CONCLUÍDA]**
  `remoteid-portas` define os 7 contratos (RepositorioEstado, CofreDeChave,
  TransporteRemoteId, Diagnostico, Relogio, Ambiente, Prompter) + `IdInstalacao`.
  Adaptadores padrão, um crate cada: `store-json` (RepositorioEstado, com prova
  de troca por um RepositorioMemoria em teste), `chave-pem` (CofreDeChave, chave
  nunca sai do cofre), `http` (TransporteRemoteId, ureq), `diag-jsonl`
  (Diagnostico), `relogio-sistema`, `ambiente-sistema`. A redação de segredos
  virou o crate puro `remoteid-redacao`; os fatos de host deixaram de estar
  duplicados no motor (fonte única). As fachadas do core delegam aos adaptadores
  (backdep temporária, invertida na Fase 3). 21 crates, 109 testes verdes.
  - **Pendente menor:** o default `nome_aplicacao` do GTK ainda repete a
    constante; deduplicar quando o motor passar a consumir aquele config.
- **Fase 3 — motor genérico. [CONCLUÍDA no essencial]** O `Motor` não contém
  mais tipos concretos: guarda `Box<dyn RepositorioEstado>`, `CofreDeChave`,
  `TransporteRemoteId`, `Arc<dyn Diagnostico>`, `Relogio`, `Ambiente` e o
  `IdInstalacao`. `Motor::abrir` monta os adaptadores padrão do desktop;
  `Motor::com_dependencias` injeta implementações arbitrárias (o gancho da versão
  central e dos testes). A interpretação da resposta ("HTTP 200 = erro") virou
  `protocolo_servidor::resposta` (pura). O `Prompter` foi unificado na porta. Um
  teste (`tests/injecao.rs`) roda o motor com um repositório EM MEMÓRIA no lugar
  do JSON e prova que a troca não toca a lógica. Os testes de integração
  (`fluxo`, `fluxo_otimista`), que verificam a assinatura do Bearer, seguem
  verdes: comportamento preservado.
  - **Polimento restante (Fase 3b/4):** mover `engine`/`Servico` para uma crate
    `remoteid-aplicacao` e inverter as backdeps temporárias (o core ainda
    re-exporta os adaptadores como fachada para `cli`/`pkcs11`/`mock`); isso é
    topologia, não muda comportamento nem capacidade.
- **Fase 4 — religar a borda de entrada.** CLI, app GTK, módulo PKCS#11 e mock
  passam a montar as portas (composition root em cada binário). Socket interno
  pode ser redesenhado aqui, se valer a pena.
- **Fase 5 — provar a troca.** Escrever um segundo adaptador trivial de estado
  (ex.: em memória, ou XML mínimo) e um teste que roda o fluxo inteiro com ele.
  É a prova executável de que o contrato isola de verdade. Fecha o escopo.

## 8. Decisões travadas

1. **Granularidade: um crate por domínio.** Isolamento físico desde já
   (`remoteid-protocolo-servidor`, `remoteid-cripto`, `remoteid-estado`,
   `remoteid-autorizacao`, `remoteid-assinatura`, `remoteid-tipos`), como no §5.1.
2. **Síncrono primeiro.** Mantém `ureq`; as portas são desenhadas neutras para
   não impedir async. Async só quando a versão central Postgres existir.
3. **Renomear sem compat.** `desktopid-*` → `remoteid-*` em crates, binários,
   `DESKTOPID_*` e diretórios. Repositório novo, começa limpo; instalações
   atuais reinstalam.
4. **Portas em crate dedicado.** `remoteid-portas` (coerente com o
   um-crate-por-domínio).

### Ainda em aberto

- **Clonar preservando o histórico git** (mais rastreabilidade) vs. cópia limpa
  (história começa aqui). A decisão 3 (repo novo, sem compat) inclina para cópia
  limpa, mas dá para preservar o histórico mesmo assim; confirmar na fase 0.

## 9. O que este documento NÃO decidiu ainda

Nomes finais de crate e de trait, assinaturas exatas das portas, e o desenho do
socket interno reescrito. Isso entra na fase 0/2.

## 10. Corpus de teste e artefatos não versionados

O testador deixou 19 relatórios do harness em `.logs/`. Cada um traz o
transcript HTTP cru (payload enviado e resposta), e a maioria falha em algum
ponto, o que os torna a melhor fonte de casos reais que existe.

**Uso na migração:**

- **Testes de ouro do `remoteid-protocolo-servidor`** (o domínio fechado):
  fixar o formato dos corpos de requisição e o parsing de cada resposta contra
  exemplos reais, para que uma "correção" futura na canônica ou nos payloads
  não passe silenciosamente.
- **Tabela de classificação de erros**: o conjunto de mensagens do servidor é
  fechado e pequeno. As distintas observadas nas runs são:
  `Usuário ou senha inválidos`, `Illegal base64 character 2e`,
  `Informe o Pin`, `Informe o e-Token(Otp)`,
  `Ocorreu um erro ao validar Credencial: Não existe autorização válida para
  este token`, `... Código de autorização inválida`,
  `could not execute statement ... ConstraintViolationException`,
  `Erro ao executar operação: Error sending apns server`, e os sucessos
  (`Token gerado com sucesso`, `Assinatura no hsm gerada com sucesso.`). Mais os
  códigos HTTP de payload malformado (400/404/405/500). A tabela `SERVER_HINTS`
  atual já cobre esse conjunto; os testes passam a ancorá-la nesse corpus.

**Regra de segurança (inegociável):** esses arquivos têm token de sessão,
certificado, CPF, nome e e-mail reais. Nunca vão para o git, e **nenhum valor
real entra em teste versionado**. As fixtures são derivadas por sanitização:
preservam a **estrutura** e as **strings de mensagem do servidor**, e trocam
todo dado do titular por valores sintéticos (o `remoteid-mock` já tem um
certificado/OTP/PIN falsos para isso).

**`.gitignore` do novo repo** exclui pelo menos: `.logs/`, `vendor/`, `target/`,
`*.installation-key.pem`, `desktopid-harness-*.txt` / `remoteid-harness-*.txt`,
`state.json` e o diretório de diagnóstico.
