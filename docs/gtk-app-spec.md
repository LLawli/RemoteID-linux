# Especificação da crate `remoteid-gtk` (a construir do zero)

A crate `remoteid-gtk` foi removida do workspace para ser reescrita do zero. Este
documento é o contrato completo: o que o app faz, com que tecnologia, como se
liga ao resto do workspace, e a função de cada tela. Construa a partir daqui, sem
depender de nenhuma implementação anterior.

## O que é o app

O `remoteid-app` é o aplicativo de desktop do RemoteID-linux: a interface para
usar o **certificado em nuvem RemoteID (Certisign)** no Linux. Ele:

1. **Prepara a instalação** (login + registro + carteira) na primeira vez.
2. **Expõe o certificado a navegadores e ao GNOME Papers**, hospedando, no
   próprio processo, um **servidor de socket UNIX** que o módulo PKCS#11
   (`remoteid-pkcs11`, um `.so`) consome no `C_Sign`.
3. **Pede PIN e OTP** numa janela quando uma assinatura precisa de autorização.

Consequência de projeto (unificação): é **um binário só**, janela + servidor do
socket no mesmo processo. **Assinar só funciona com a janela aberta.**

## Tecnologia (obrigatória)

- **Rust**, crate `remoteid-gtk` (lib + binário `remoteid-app`), membro do
  workspace.
- **GTK4** (`gtk4` 0.9) **+ libadwaita** (`libadwaita` 0.7, feature `v1_4` no
  mínimo; o sistema tem adw 1.9). App = `adw::Application` (inicializa os estilos).
- **Siga o GNOME HIG** e o idioma libadwaita: `AdwApplicationWindow`,
  `AdwToolbarView` + `AdwHeaderBar` (um header por view), `AdwPreferencesPage`/
  `AdwPreferencesGroup`/`AdwActionRow`/`AdwEntryRow`/`AdwPasswordEntryRow`/
  `AdwSpinRow`/`AdwComboRow`, `AdwStatusPage`, `AdwClamp` (conteúdo clampado a
  ~600px e centralizado, nunca esticado de ponta a ponta), `AdwAlertDialog` para
  confirmações, ícones simbólicos, classes de estilo (`pill`, `suggested-action`,
  `destructive-action`, `boxed-list`, `property`). Nada de rótulos crus
  selecionáveis nem números de debug (epoch/hash) na cara do usuário.
- Tudo em **português do Brasil** (rótulos, mensagens), como o resto do projeto.

## Como se liga ao workspace (contratos, não copie UI antiga)

Dependa destes crates e use as APIs abaixo:

- **`remoteid-daemon`** — a camada de serviço. É livre de GTK.
  - `remoteid_daemon::servico::Servico`: `Servico::novo(opcoes, Box<dyn Prompter>) -> Result<Servico>`,
    `servico.tratar(Requisicao) -> Resposta`, `servico.reabrir() -> Result<()>`
    (relê o estado do disco depois do `preparar`), `servico.deve_encerrar() -> bool`.
    A janela fala com o `Servico` **direto** (sem socket consigo mesma).
  - `remoteid_daemon::prompter::{Prompter, Contexto}` (re-export de
    `remoteid-portas`): o trait que você implementa para pedir PIN/OTP.
    `Prompter::pedir_pin_otp(&self, &Contexto) -> Result<Fatores>`;
    `Contexto { hospedeiro: Option<String>, titular: Option<String> }`.
  - `remoteid_daemon::socket`: `caminho_padrao() -> PathBuf` e
    `bind_manual(&Path) -> io::Result<UnixListener>`. É o socket que o módulo
    PKCS#11 usa. Você sobe o listener não-bloqueante e o integra ao loop do glib
    (watch de FD), atende cada conexão na thread principal, e usa `try_borrow_mut`
    no `Servico` para **nunca reentrar** (uma assinatura em curso => responda
    "ocupado"). Uma mensagem JSON por linha (`\n`).
- **`remoteid-protocolo`** — o protocolo do socket (JSON). É seu para redesenhar
  se quiser, mas hoje é: `Requisicao::{Sign{digest_b64, hospedeiro?}, Status,
  ReautorizarProxima, EscolherCertificado{key_name}, Reinstalar, Encerrar}` e
  `Resposta::{Sucesso(SucessoResposta), Falha{ok, erro, codigo: CodigoErro}}`.
  `SucessoResposta::Status{ preparado, titular?, codigo_desktop?, certificados:
  Vec<CertificadoResumo{key_name, serial_number, issue}>, certificado_ativo?,
  sessoes: Vec<SessaoResumo{cert_key, emitido_em?, visto_em}> }`,
  `SucessoResposta::{Sign{assinatura_b64, cache_hit}, Ack}`.
- **`remoteid-aplicacao`** — `Opcoes` (via `Opcoes::default()`, que já respeita
  `TEST_URL`). É o que você passa a `Servico::novo`.
- **`remoteid-caminhos`** — `em_teste() -> bool` (modo de teste), para o título
  da janela e afins.
- **`remoteid-autorizacao`** — `Fatores` (`Fatores::PinOtp{pin, otp}`), o retorno
  do `Prompter`.
- **`remoteid-tipos`** — `Error`/`Result`.
- **NUNCA** faça o módulo PKCS#11 depender do GTK (ele é um `cdylib`); a ponte é
  só o `remoteid-protocolo` pelo socket.

Preparação: rode o binário `remoteid` (a CLI) com `remoteid preparar`, passando
`REMOTEID_EMAIL`/`REMOTEID_SENHA` por **variável de ambiente (nunca por argv**,
que aparece em `ps`); depois chame `servico.reabrir()`.

Modo de teste: quando `TEST_URL` está setada, estado/diag/socket vão para `/tmp`
e o servidor é o `remoteid-mock` (nada toca a conta real). O título da janela
deve indicar "MODO DE TESTE". App-ids sugeridos: `dev.lukakuuhaku.RemoteID`
(+ `.Preview`, `.Teste`).

## As telas (função de cada uma)

Todas em `AdwPreferencesPage`/grupos clampados, cada uma com seu `AdwHeaderBar`.

1. **Login / instalação** (primeiro uso, quando não preparado). Coleta e-mail e
   senha do RemoteID e um botão "Preparar instalação", que dispara o `remoteid
   preparar` (login + registro do desktop + carteira). Deixe claro que a senha
   vai só ao RemoteID e não é guardada. Sugestão: `AdwStatusPage` de boas-vindas
   + `AdwPreferencesGroup` com `AdwEntryRow` (e-mail) e `AdwPasswordEntryRow`
   (senha); botão só acende com os dois preenchidos. (A tela de login anterior
   tinha sido APROVADA visualmente, então este layout é um bom alvo.)

2. **Painel inicial** (quando preparado). Mostra, em grupos/linhas claras:
   - **Identidade**: titular e código do desktop (com botão de copiar).
   - **Certificado(s)**: o(s) da carteira; com mais de um, marque o ativo com um
     visto e ofereça "Trocar certificado".
   - **Assinatura**: o estado da próxima assinatura em linguagem humana — se há
     sessão em cache, diga até quando (data legível, nunca epoch/hash); senão,
     "vai pedir PIN e OTP". Ação "Reautorizar próxima assinatura" (descarta a
     sessão cacheada).
   - A **engrenagem de Configurações** no `AdwHeaderBar` (não no corpo).

3. **Seleção do certificado padrão** (quando a carteira tem >1 e nenhum foi
   escolhido; também acessível por "Trocar certificado"). É a **opção A,
   persistente**: o usuário escolhe um certificado padrão, que o serviço grava
   (`Requisicao::EscolherCertificado{key_name}`) e o motor passa a usar. Liste
   cada certificado como linha selecionável (rádio), com confirmação visual do
   que está marcado e um botão para confirmar. Marque o ativo atual.

4. **Configurações**. Cache do PIN (min; 0 desliga), TTL da sessão (min), nome do
   aplicativo, e — quando há >1 certificado — "Certificado de assinatura" (abre a
   seleção). Grupo "Diagnóstico" com a pasta do log (botão Abrir). "Zona de
   perigo" com **Reinstalar** (destrutivo; confirme com `AdwAlertDialog`; apaga o
   estado local e a chave, preserva o log). Voltar e Salvar no header.

5. **PIN / OTP (assinar)** — a MAIS crítica; é o que o testador vê ao assinar, e
   o pagamento de todo o projeto é assinar sem crash.
   - Mostrada pelo `Prompter` quando um `Sign` do módulo PKCS#11 precisa de
     autorização. Campos: **PIN** (senha; pode vir pré-preenchido de um cache em
     memória com TTL ~5 min) e **OTP** (dígitos, de uso único, **nunca cacheado**).
     "Assinar" só ativa com os dois. Cabeçalho "Assinar como <titular>", legenda
     "Solicitado por <app>".
   - **REQUISITO DE JANELA (Hyprland e afins):** deve ser um diálogo que
     **flutua acima da janela que pediu, fora do tiling** — do tipo "notice"/
     dialog, não uma janela normal (que o compositor tila). Modal, não
     redimensionável, transiente a uma janela real do app. Siga o HIG para
     diálogos de autenticação.
   - **Cuidado de concorrência:** a chamada de assinatura chega pela thread
     principal, vinda do handler do socket, enquanto o app roda. O diálogo não
     pode reentrar no `Servico` nem travar o loop de forma a impedir a resposta.
     (A implementação anterior usava um loop aninhado do glib; você pode escolher
     outra abordagem, desde que o requisito acima seja atendido.)
   - Cancelar => o `Prompter` devolve erro "cancelado"; o serviço traduz para
     `CodigoErro::Cancelado`.

## Modo `--preview`

Um modo (arg `--preview`) que abre as telas com **dados fictícios** (sem motor,
sem socket), para validação visual rápida. Preferência do usuário: **uma janela
por tela, todas abertas de uma vez** (não uma galeria com abas). As ações só
registram no stdout.

## Segurança (inegociável)

PIN, OTP e senha **nunca** em log, argv ou disco. Senha só por variável de
ambiente ao chamar a CLI. O OTP nunca é cacheado.

## Validação

`remoteid-gtk` é crate folha: rode `cargo test -p remoteid-gtk` e
`cargo clippy -p remoteid-gtk` (ninguém depende dela). Ver a regra de escopo por
cone de dependentes no `CLAUDE.md`.
