# Arquitetura

Para quem vai mexer no projeto. O que ele resolve, e para quem, está no
[README](../README.md).

## A divisão

O RemoteID é uma extensão de driver do Âncora
(`dev.lukakuuhaku.Ancora.Driver.RemoteID`, montada em
`/app/extensoes/driver/RemoteID`). O contrato da extensão (o `ancora.toml`, os
pontos de extensão, as regras) é do Âncora, em
`~/Personal/adv-central/docs/extensoes.md`. Publicar o módulo no p11-kit do
host, criar o atalho de menu e distribuir ficam com o Âncora; este projeto não
tem instalador próprio.

A extensão traz duas peças, as duas rodando no sandbox do Âncora:

| peça | o que é | quem a usa |
|---|---|---|
| `lib/libremoteid.so` | o módulo PKCS#11, sem GTK, com o motor inteiro: estado, sessão em cache e a conversa com a Certisign | o `p11-kit server` que o `ancora servir` mantém no ar, e por ele os navegadores, o leitor de PDF e os assinadores |
| `bin/remoteid` | a janela (entrar na conta, certificados, configurações), o diálogo de PIN e OTP, e os subcomandos de terminal | a pessoa, pelo atalho que o Âncora cria; o módulo, para pedir PIN e OTP |

**Assinar não depende da janela aberta.** Basta o que o Âncora mantém sempre
ativo, o `ancora servir` publicando o driver. A chave do certificado fica no HSM
da Certisign. No `C_Sign` o módulo, dentro do serviço do Âncora, usa a sessão
em cache ou, quando ela não vale mais, abre só o diálogo de PIN e OTP
(`remoteid` num modo de pedido, um processo que vive o tempo da pergunta), fala
com o servidor e devolve a assinatura. A janela só é necessária para entrar na
conta e configurar.

Diferença para o RemoteID-linux, onde o motor morava no aplicativo e o módulo
falava com ele por socket: lá, com o aplicativo fechado, o certificado aparecia
e toda assinatura falhava.

## A organização

Um pacote Cargo só. A biblioteca é ao mesmo tempo o `cdylib` que o p11-kit
carrega e o `rlib` que o binário usa; o GTK é dependência só do binário. Medido
em 2026-10-30: o `.so` sai ligado apenas a `libc`, `libgcc_s` e `ld-linux`.

O RemoteID-linux tinha 23 crates, com uma porta (trait) para cada efeito,
pensadas para uma versão central multi-conta que nunca existiu. Aqui os
domínios são módulos, e uma trait só existe quando há duas implementações de
verdade hoje (a real e a de teste): o `Transporte` (HTTP ou falso) e o
`Autorizador` (o diálogo de PIN e OTP, ou fatores fixos num teste).

| módulo | o que faz |
|---|---|
| `protocolo/` | monta as requisições e lê as respostas; puro, provado contra o antigo |
| `cripto` | a chave da instalação, que assina o `Bearer` |
| `transporte` | leva a requisição pela rede (ureq) |
| `estado` | conta, registro, carteira e sessões em cache, num JSON 0600 |
| `caminhos` | onde fica cada arquivo, e o servidor (`REMOTEID_SERVIDOR` troca pelo falso) |
| `motor` | o fluxo: preparar a conta e assinar, com a sessão em cache |
| `pkcs11/` | o módulo Cryptoki: o token montado do estado, e o `C_Sign` pelo motor |
| `pedido` | o `Autorizador` do módulo: abre o `remoteid pedir` e lê o PIN e o OTP por pipe |
| `x509` | os campos do certificado que o token publica, e o nome do titular |
| `cadeia` | as autoridades do certificado, do `caIssuers` até a raiz; puro, o download é do motor |
| `diagnostico` | um JSONL por execução, com segredos e dados do titular redigidos |
| `bin/remoteid-mock` | o servidor falso dos testes |

O motor roda em dois processos que dividem o mesmo estado em disco: o módulo,
no serviço do Âncora, e a janela. Cada um relê o estado antes de agir
(`Motor::recarregar`); a escrita é por troca atômica, então ninguém lê um
arquivo pela metade. Toda escrita passa por `Estado::alterar`, que relê o
arquivo sob uma trava (`estado.trava`, com `flock`) e aplica só a mudança: o
módulo guarda a sessão nova depois de um diálogo que pode ter levado um minuto,
e gravar a cópia lida antes apagaria o que a janela mudou nesse tempo. A trava
dura o tempo de ler e gravar, nunca o de uma pergunta à pessoa, e quem só lê
não a pega.

## O módulo dentro do `p11-kit server`

O `p11-kit server` do Âncora abre um `p11-kit-remote` por conexão, e cada um
carrega o módulo do zero: o navegador tem o seu, o leitor de PDF o dele, e a
sonda da supervisão abre um novo a cada 10 s. Daí as regras do módulo:

- **Listar não custa nada.** O `C_Initialize` só lê o `estado.json`: não gera a
  chave da instalação, não cria arquivo de diagnóstico, não vai à rede. O motor
  é aberto na primeira assinatura.
- **Nenhuma trava segura a pessoa.** O `C_Sign` tira a operação da sessão sob a
  trava do módulo e assina sem ela, então o mesmo aplicativo continua listando
  tokens enquanto o diálogo está aberto. Duas assinaturas do mesmo processo
  esperam uma pela outra no motor, e a segunda aproveita a sessão da primeira.
  Como a sonda tem processo próprio, um `C_Sign` esperando a pessoa não a
  atrasa, e a supervisão não precisa de campo novo no contrato. Medido na VM
  Fedora 44 em 2026-10-30, com só o `ancora servir` no ar: o diálogo ficou
  mais de 4 minutos aberto, o driver continuou publicado, e listar tokens nesse
  tempo levou 0,08 s.
- **Sempre há token.** Sem conta, o slot tem um token não inicializado e sem
  objetos, como o slot livre do SoftHSM. Um slot sem token faz o
  `C_GetSlotList(CK_TRUE)` devolver a lista vazia, e pelo RPC do p11-kit
  0.26 a segunda passada com zero itens volta `CKR_BUFFER_TOO_SMALL`: quem
  repete enquanto o buffer é pequeno, como o `get_slots_with_token` do crate
  `cryptoki` que a sonda do Âncora usa, fica em laço para sempre. Na VM, isso
  parou o driver em três sondas e levou a carga a 16.
- **O diálogo é outro processo.** `remoteid pedir`, achado ao lado do `.so`
  (`../bin/remoteid`, pelo `/proc/self/maps`), recebe o nome do titular pelo
  stdin e devolve o PIN e o OTP pelo stdout, nunca por argumento nem ambiente.
  O stdout do módulo é o canal do p11-kit com o aplicativo, e por isso o
  diálogo nunca o herda. Fechar a janela, ou cinco minutos sem resposta, é
  `CKR_FUNCTION_CANCELED`.
- **O token assina com o certificado que mostra**, e não com o ativo do
  momento: se a janela trocar a escolha com o aplicativo aberto, a assinatura
  ainda confere com o certificado que ele leu.
- **O token acompanha a conta numa conexão aberta.** O navegador mantém a
  conexão o tempo todo, então o módulo confere a identidade do `estado.json`
  (inode e data, que a troca atômica renova) nas chamadas de slot e token. Uma
  gravação que não troca o certificado, como a de cada assinatura, não muda
  nada; trocar o certificado, entrar ou sair da conta derruba as sessões, como
  tirar um cartão e pôr outro. O slot se anuncia removível, que é o que faz o
  NSS voltar a conferi-lo e, achando a sessão inválida, reler o token.
- **A cadeia vai junto.** O token publica, depois do titular, as autoridades
  que o motor baixou do `caIssuers` ao atualizar a carteira, com
  `CKA_CERTIFICATE_CATEGORY` de autoridade e `CKA_ID` próprio, para o
  SunPKCS11 montar a cadeia pelo `CKA_SUBJECT` sem ir à rede (o assinador do
  Projudi precisa). Uma AC fora do ar não impede a carteira: fica a cadeia que
  o certificado já tinha, ou nenhuma.

Do RemoteID-linux vêm, com o motivo em comentário no código, as escolhas que
os hospedeiros exigem: o token não anuncia login (o NSS pedia o PIN em laço), o
`CKM_RSA_PKCS` anuncia cifra (o SunPKCS11 do PJeOffice precisa), e a assinatura
em fluxo (`C_SignUpdate`) existe porque o BouncyCastle nunca chama `C_Sign`.

## O protocolo com a Certisign não muda

O que o servidor RemoteID aceita não está sob nosso controle. Tem de sair igual
ao do RemoteID-linux, byte a byte:

- os corpos das requisições, byte a byte, e os endpoints;
- o `Bearer`: a assinatura, com a chave da instalação, da forma canônica do
  corpo (regra decompilada do app oficial: chaves em ordem alfabética, e um
  `true` escreve o nome da chave);
- o `USER_AGENT` `desktopID/2.2.0.1`, que imita o aplicativo oficial;
- o `sessionToken` opaco, e a regra de que HTTP 200 pode ser erro.

O código pode ser reescrito; a prova de que nada mudou é
`tests/paridade.rs`. Ele compara o código novo, 1:1, com fixtures gravadas
rodando o próprio RemoteID-linux v0.3.2: cada requisição (método, URL,
cabeçalhos e corpo em bytes, com o `Bearer` assinado pela mesma chave de
teste), o que foi lido de cada resposta, a classificação de cada mensagem de
erro e a canônica. As fixtures saem de `paridade/`, um projeto à parte que
depende do antigo; o porquê e como regenerar estão em
[paridade/README.md](../paridade/README.md).

Por que fixtures, e não o antigo como dependência de teste do pacote: medido em
2026-10-30, isso levaria o `Cargo.lock` de 68 para 205 pacotes, todos no build
offline do Flatpak, e o builder e a CI precisariam de credencial para o
repositório privado. Os testes conseguem falhar: sete de oito defeitos
plausíveis injetados no código novo foram pegos, e o oitavo (um `true`
escrevendo "true" na canônica) virou a fixture `canonica.json`, porque nenhum
corpo do caminho PIN+OTP tem `true`.

Também vem do antigo, como regra: PIN, OTP e senha nunca vão para log, teste ou
documentação, e o diagnóstico só grava o que já passou pela redação.

## Plano de construção

1. **Fundação** (feito): este esqueleto, os gates, a CI e o manifesto da
   extensão.
2. **Protocolo** (feito): requisições, canonicalização, `Bearer` e leitura das
   respostas (`src/protocolo/`), com os testes de paridade contra o
   RemoteID-linux.
3. **Motor e servidor falso** (feito): preparar (login, registro do desktop e
   carteira), estado, sessão em cache, assinar, diagnóstico redigido, e o
   servidor RemoteID falso que os testes usam. O servidor falso confere o
   `Bearer` com a chave do registro e lembra as sessões, e o transporte novo
   manda os mesmos bytes e cabeçalhos que o antigo.
4. **Módulo PKCS#11 com o motor dentro e o diálogo de PIN e OTP sob demanda**
   (feito), testados com só o `ancora servir` no ar (nenhuma janela aberta), por
   `pkcs11-tool` contra o servidor falso.
5. **Interface**: entrar na conta, painel, PIN e OTP, escolha do certificado,
   configurações.
6. **Terminal**: `remoteid assinar` (inclusive o `.p7s` CAdES-BES com
   `signingCertificateV2`) e o harness de diagnóstico.
7. **Publicação**: no remote do Âncora, no lugar da extensão RemoteID do
   flatpak-adv-br.

Fora da primeira versão: a aprovação por celular (push). Está implementada no
RemoteID-linux e nunca passou por uma conta real.

## Em aberto

- **A sonda do Âncora em laço com driver sem token.** O laço acima pega
  qualquer driver sem token, uma leitora sem cartão por exemplo; o RemoteID
  se protege, mas a correção é do Âncora (pedir os slots sem filtro e olhar
  `CKF_TOKEN_PRESENT`, ou não repetir com contagem zero).
- **O sandbox do Âncora não tem rede.** O motor fala HTTPS com a Certisign de
  dentro do `p11-kit server` do Âncora, e o manifesto dele não tem
  `--share=network` (o do flatpak-adv-br tinha). Uma extensão não acrescenta
  permissões: sem a rede no Âncora, toda assinatura falha.
- **O acompanhamento do token não foi visto num navegador.** O teste prova o
  lado do módulo (sessões derrubadas quando o certificado muda); que o NSS
  então relê o token é o que o código dele diz para slots removíveis, e falta
  conferir num Firefox aberto.
- **O serviço do Âncora com a sessão.** Hoje o `ancora servir` não sobe sozinho
  no login (pendência do Âncora); até lá, o RemoteID só assina com ele no ar.

## O repositório

O código vive no repositório do RemoteID-linux (`LLawli/RemoteID-linux`), que
ele substitui. Até a publicação, a reescrita fica no branch `reescrita-ancora`,
com histórico próprio; a `main` continua sendo a v0.3.2. Na etapa 7 ela entra na
`main` por pull request, num commit que troca a árvore inteira, e o histórico,
as tags e as releases da versão anterior ficam onde estão.
