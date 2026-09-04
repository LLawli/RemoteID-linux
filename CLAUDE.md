# RemoteID-linux — instruções do projeto

Cliente para o certificado em nuvem **RemoteID / DesktopID** (Certisign) no
Linux, onde não há app oficial. O protocolo foi reconstruído por engenharia
reversa do app de macOS e confirmado ao vivo. Este repositório é a reconstrução
do antigo `DesktopID-linux` sob uma arquitetura de núcleo funcional e portas.

## Memória e handoff: ai-memory

Este projeto **usa o ai-memory** para memória e handoff (recall no início da
sessão, salvar decisões e handoff no fim). Não versionar memória em arquivos.
As páginas em `docs/PROTOCOLO.md`, `docs/PAYLOADS.md` e
`docs/ARQUITETURA-SO.md` são **documentação de referência** da engenharia
reversa (o que o servidor faz e por quê), não o sistema de memória.

As notas de sessão que viviam em `docs/memoria/` saíram do repositório em
04/09/2026, antes da publicação: elas citam caminhos da máquina e são raciocínio
de trabalho, não documentação do projeto. Ficam em
`../RemoteID-linux-memoria/`, fora do git. Comentários no código referenciam
essas notas na forma `[[nome-da-nota]]`, que é uma chave do ai-memory, não um
caminho de arquivo — não transforme em link.

## Arquitetura (as regras desta reconstrução)

**Functional Core, Imperative Shell + Portas e Adaptadores (hexagonal).**

- **Um crate por domínio.** O núcleo é isolado fisicamente, não só por módulo.
- **Núcleo puro:** funções que recebem valor e devolvem valor, sem I/O dentro
  delas. Testáveis isoladamente, sem rede, sem disco, sem `std::env`, sem
  relógio do sistema.
- **Bordas imperativas:** os adaptadores cuidam de todo o I/O (disco, rede,
  relógio, ambiente, UI, FFI).
- **Contratos (traits/portas)** entre os dois, para trocar implementação sem
  tocar no núcleo: `RepositorioEstado`, `CofreDeChave`, `TransporteRemoteId`,
  `Diagnostico`, `Relogio`, `Ambiente`, `Prompter`.
- **A chave privada nunca sai do cofre.** `CofreDeChave` expõe `assinar`, nunca
  a chave crua. É o que viabiliza um adaptador Postgres/HSM sem vazar segredo
  para o núcleo.
- **Portas de estado e chave são endereçadas por identidade de instalação/conta**
  (`IdInstalacao`), não por instalação global única. É o que deixa uma futura
  versão central multi-conta (Postgres) cair fora sem mudança quebradora.
- **Síncrono primeiro.** As portas são desenhadas neutras para não impedir async
  depois; async só quando a versão central existir.

O mapa completo, o grafo de crates e o plano faseado estão em
[docs/escopo-migracao.md](docs/escopo-migracao.md).

## O que NÃO pode mudar, e o que é livre

- **Imutável: o protocolo de comunicação com o servidor RemoteID.** Não está sob
  nosso controle. Paridade byte a byte: corpos das requisições, endpoints,
  canonicalização, a assinatura do `Bearer` (cobre os bytes exatos do corpo
  serializado, nunca reserializar), o `USER_AGENT` `desktopID/2.2.0.1` (imita o
  app oficial), o formato opaco do `sessionToken`, e "HTTP 200 pode ser erro".
  Esse domínio é **fechado**, coberto por testes de ouro.
- **Livre para redesenhar:** o protocolo do socket interno (app ↔ módulo
  PKCS#11), o CLI, os formatos de armazenamento, as traits, os nomes.

## Fonte única (DRY)

O que se repete tem de morar em UM lugar, para mudar em um ponto e não em vinte.
O endereço do servidor já é fonte única (as constantes de URL e os templates de
endpoint no domínio do protocolo). O mesmo vale para o nome do app e os caminhos
de diretório: o núcleo é a fonte, e a borda referencia, nunca hardcoda de novo.

## Convenções

- **Idioma:** tudo em português do Brasil (comentários, docs, mensagens de erro,
  nomes de teste). Identificadores de código e chaves de protocolo ficam na forma
  original (`codigoDesktop`, `nomeAplicacaoDesktop`, `signatureBase64`).
- **Comentários explicam o porquê**, principalmente quando o código parece errado
  e não está (a maior parte deste protocolo é contraintuitiva).
- **Formatação:** o estilo é o do `rustfmt` padrão, sem discussão e sem
  `rustfmt.toml`. O repositório não briga com o formatador: `cargo fmt --all` é
  a autoridade, e `cargo fmt --all --check` é gate no CI. Escreveu, formatou.
- **Licença:** GPLv3-only.
- **Commits:** assinados por SSH, sem co-autoria de IA, escopo por mudança
  lógica. Só commitar quando o usuário pedir.

## Segurança, que aqui não é abstrata

- **Nunca** gravar PIN, OTP ou senha em log, transcript, teste ou documentação.
  O PIN do certificado é permanente. A forma canônica assinada contém PIN e OTP
  concatenados: registre o hash dela, nunca o texto.
- A redação de segredos é regra de **domínio** (pura e testável); o `Diagnostico`
  só persiste o que já foi redigido.
- **`.logs/` nunca é versionado.** Contém runs reais com token de sessão,
  certificado, CPF, nome e e-mail. Nenhum valor real entra em teste versionado:
  as fixtures são sintéticas (`remoteid-mock` tem cert/OTP/PIN falsos).
- `vendor/` tem os instaladores oficiais. Fora do git, não redistribuir.

## Validação: escope pelo cone de dependentes, nunca pelas dependências

A dependência do workspace só aponta para BAIXO: domínio (`tipos`, `cripto`,
`autorizacao`, `estado`, `assinatura`, `protocolo-servidor`, `redacao`) ← portas
← adaptadores ← `aplicacao` ← borda (`cli`, `gtk`, `pkcs11`, `daemon`, `mock`).
**Um componente de baixo nível NUNCA depende de um de alto nível.** Se você se
pegar querendo importar `remoteid-aplicacao` de dentro de `remoteid-estado`, pare:
a inversão está errada.

Disso sai a regra de teste. Ao mexer numa crate, rode `cargo test`/`cargo clippy`
**dela e de tudo que depende dela (o cone para CIMA), nunca das suas
dependências (para baixo)**:

- **Mudança de base** (ex.: `remoteid-estado`, `remoteid-tipos`, uma porta):
  roda a suíte de TODOS os componentes de alto nível que a usam. Mexer em
  `estado` roda `store-json`, `protocolo-servidor`, `aplicacao`, `daemon`,
  `gtk`, `pkcs11`, `cli` — porque a mudança pode quebrá-los.
- **Mudança de alto nível** (ex.: `remoteid-gtk`, folha): roda só a própria
  crate. Um botão torto no GTK não muda o SHA-256 do domínio, então **não** roda
  `estado` nem `aplicacao`. Ninguém depende do GTK; o cone para cima é ele mesmo.

Na prática: `cargo test -p <crate-tocada> -p <dependente-1> -p <dependente-2> ...`.
O gate completo (`make check` = `cargo test && cargo clippy --all-targets &&
cargo build --release`) é quando a mudança toca uma base cujo cone é
praticamente o workspace inteiro, ou antes de um commit que cruza várias crates.
