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
| `bin/remoteid` | a janela (entrar na conta, a carteira em cartões), o diálogo do código do autenticador, e os subcomandos de terminal | a pessoa, pelo atalho que o Âncora cria; o módulo, para pedir PIN e OTP |

**Assinar não depende da janela aberta.** Basta o que o Âncora mantém sempre
ativo, o `ancora servir` publicando o driver. A chave do certificado fica no HSM
da Certisign. No `C_Sign` o módulo, dentro do serviço do Âncora, usa a sessão
em cache ou, quando ela não vale mais, abre só o diálogo do código do autenticador
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
`Autorizador` (o diálogo, ou fatores fixos num teste) e o `Cofre` (o chaveiro
do sistema, ou um na memória).

| módulo | o que faz |
|---|---|
| `protocolo/` | monta as requisições e lê as respostas; puro, provado contra o antigo |
| `cripto` | a chave da instalação, que assina o `Bearer` |
| `transporte` | leva a requisição pela rede (ureq) |
| `estado` | conta, registro, carteira e sessões em cache, num JSON 0600 |
| `caminhos` | onde fica cada arquivo, e o servidor (`REMOTEID_SERVIDOR` troca pelo falso) |
| `motor` | o fluxo: preparar a conta e assinar, com a sessão em cache |
| `pkcs11/` | o módulo Cryptoki: o token montado do estado, e o `C_Sign` pelo motor |
| `pedido` | o `Autorizador` do módulo: abre o `remoteid pedir` e lê os fatores por pipe |
| `cofre` | a senha da conta no chaveiro do sistema (`oo7`: portal de segredos, ou Secret Service) |
| `pin` | sem chaveiro, a senha cifrada no disco com um PIN local |
| `carteira` | o que a janela mostra, montado do estado: cartões, sessão, validade, cadeia |
| `x509` | os campos do certificado que o token publica, e o nome do titular |
| `cadeia` | as autoridades do certificado, do `caIssuers` até a raiz; puro, o download é do motor |
| `diagnostico` | um JSONL por execução, com segredos e dados do titular redigidos |
| `cades` | o `.p7s` em duas fases, com a ida ao HSM no meio, na política AD-RB; sem política, igual byte a byte ao do antigo |
| `harness` | o fluxo com a conta entrada, passo a passo, e o relatório para enviar |
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
- **A rede é a do Âncora.** O motor fala HTTPS com a Certisign, e baixa a
  cadeia, de dentro do sandbox do `ancora servir`; uma extensão não acrescenta
  permissões, e o Âncora tem `--share=network` para isso desde `bbfbfaf`. Na
  VM, com o servidor falso numa instância separada, entrar, baixar a cadeia
  (3 certificados no token) e assinar passaram.
- **Sempre há token.** Sem conta, o slot tem um token não inicializado e sem
  objetos, como o slot livre do SoftHSM. Um slot sem token faz o
  `C_GetSlotList(CK_TRUE)` devolver a lista vazia, e pelo RPC do p11-kit
  0.26 a segunda passada com zero itens volta `CKR_BUFFER_TOO_SMALL`: quem
  repete enquanto o buffer é pequeno, como o `get_slots_with_token` do crate
  `cryptoki` que a sonda do Âncora usa, fica em laço para sempre. Na VM, isso
  parou o driver em três sondas e levou a carga a 16. O Âncora corrigiu a
  sonda (`bbfbfaf`, lista os slots pela chamada crua), e o token não
  inicializado fica: protege qualquer outro hospedeiro que use o `cryptoki`
  pelo RPC do p11-kit.
- **O diálogo é outro processo.** `remoteid pedir`, achado ao lado do `.so`
  (`../bin/remoteid`, pelo `/proc/self/maps`), recebe o nome do titular pelo
  stdin e devolve o OTP (e, quando pedidos, a senha da conta ou o PIN local)
  pelo stdout, nunca por argumento nem ambiente.
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
  Medido num Firefox 159 aberto (Fedora 44, perguntando ao NSS dele a cada
  2 s): o certificado e a cadeia apareceram na primeira leitura depois de
  entrar, sumiram na primeira depois de sair e voltaram ao entrar de novo.
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
5. **Interface** (feito): a janela na direção "Carteira" (o certificado que
   assina é um cartão com o selo da sessão; trocar é passar o cartão; os
   detalhes sobem de baixo), escolhida entre três mocks; a senha da conta no
   chaveiro, ou cifrada com um PIN local; o diálogo pedindo só o código do
   autenticador. Testada na VM com a extensão instalada, dirigida pelo
   teclado.
6. **Terminal** (feito): `remoteid assinar` (inclusive o `.p7s` na AD-RB
   da ICP-Brasil) e o harness de diagnóstico, testados na VM
   dentro do sandbox do Âncora.
7. **Publicação**: no remote do Âncora, no lugar da extensão RemoteID do
   flatpak-adv-br. A reescrita está na `main`, na versão 0.4.0; a extensão sobe
   com o `bin/publicar` do Âncora, na migração dele, e a tag `v0.4.0` sai
   depois disso.

Fora da primeira versão: a aprovação por celular (push). Está implementada no
RemoteID-linux e nunca passou por uma conta real.

## O terminal

`remoteid assinar` lê o documento do stdin e escreve a assinatura no stdout,
porque o sandbox do Âncora não enxerga a pasta pessoal. O `.p7s` sai do
montador do RemoteID-linux (`src/cades.rs`), igual byte a byte
(`tests/paridade/cades.json`), mais o `sigPolicyId` da AD-RB v2.4, que o
antigo não tinha. O `openssl cms -verify` o aceita com a cadeia de teste. A
assinatura usa a sessão em cache como o token.

A AD-RB v2.4 (o arquivo da política, lido em 2026-10-31) e a tabela A.2 do
DOC-ICP-15.03 v9.0 exigem `contentType`, `messageDigest`,
`signingCertificateV2` e `sigPolicyId`, e só o certificado do titular no
envelope (`signerOnly`): a cadeia não vai, embora a carteira a tenha. O hash
no `sigPolicyId` é o interno da política (o SHA-256 do algoritmo mais o
`signPolicyInfo`), não o do arquivo que a LPA publica (Nota 2); a cópia em
`tests/icp-brasil/` o prova. O `signingTime` fica: no CAdES ele não é exigido
nem proibido. A política aceita cadeias até a AC Raiz v5 e a v12, e só
assinaturas RSA de 2048 bits ou mais.

Os fatores são pedidos no `/dev/tty`, sem eco, e na janela do módulo quando o
terminal não serve. Dentro do Flatpak ele quase nunca serve: medido na VM em
2026-10-31, o Flatpak 1.18.4 só deixa o app no grupo em primeiro plano do
terminal quando stdin, stdout e stderr são todos o terminal (o 1.18.2 deixava
sempre). O `assinar` redireciona a saída, então fica em segundo plano, e ler
ou mexer no terminal dali para o processo com SIGTTOU. Com SIGTTIN e SIGTTOU
ignorados, a leitura volta EIO, e o pedido vai para a janela. Não dá para
saber antes pelos números de grupo: dentro do namespace de PID do sandbox, o
do processo e o do terminal aparecem os dois como 0. Tomar o primeiro plano
(`setpgid` mais `tcsetpgrp`) contornaria uma escolha do Flatpak e não teria
como devolver o terminal ao grupo de antes, invisível dali.

`remoteid harness` não redireciona nada e pergunta no terminal mesmo no
Flatpak.

## A senha da conta

O que o servidor chama de PIN, no pedido da sessão de assinatura, é a senha da
conta RemoteID, a mesma do login e do aplicativo de celular; o fator que
autentica de verdade é o OTP. O campo do protocolo continua `pin`, e o servidor
falso agora exige nele a senha da conta.

- **No chaveiro.** Ao entrar, a senha vai para o chaveiro do sistema pelo
  `oo7`: dentro do Flatpak, o portal de segredos (um arquivo cifrado por
  aplicativo, no sandbox do Âncora, que o módulo e a janela dividem); sem o
  portal, o Secret Service do host pelo D-Bus. A assinatura então pede só o
  OTP. O `oo7` 0.6 promete essa queda para o D-Bus e não a faz (devolve o erro
  do portal antes); a queda está em `cofre.rs`. Medido na VM em 2026-10-30:
  com o portal (sessão GNOME) e com o D-Bus (sessão sem portal, com a
  permissão), as duas assinaturas pediram só o OTP.
- **Sem chaveiro**, a senha vai cifrada para `senha.cifrada` com um PIN de 4 a
  6 dígitos que a pessoa cria logo depois de entrar (Argon2id de 64 MiB e três
  passadas, ChaCha20-Poly1305 com o e-mail como dado associado). O PIN é
  pedido na primeira assinatura de cada processo, e a senha aberta fica na
  memória dele até ele fechar. Cinco PINs errados seguidos apagam o arquivo e
  saem da conta. O limite só vale aqui dentro: quem copiar o arquivo testa os
  PINs fora, atrasado só pelo Argon2id.
- **Recusa do servidor.** Ele não diz se o errado foi a senha ou o OTP; depois
  de uma recusa, o diálogo mostra a senha guardada preenchida, para confirmar
  ou corrigir, e a senha nova que o servidor aceita substitui a guardada.

## Em aberto

- **O chaveiro num desktop sem portal de segredos.** No Hyprland medido nesta
  máquina, o portal não atende `org.freedesktop.portal.Secret`, e o Âncora não
  tem `--talk-name=org.freedesktop.secrets`: o RemoteID cai no PIN local. Com
  a permissão no Âncora, o Secret Service do host (o `gnome-keyring`) atende.
- **Configurações.** A janela tem reautorizar, sair e sobre; não há tela de
  configurações, porque nada mais é configurável hoje.
- **`cargo audit`**: o `zvariant`, o `zvariant_derive` e o `zbus_names`, que
  vêm com o `oo7`, foram marcados como sem manutenção (RUSTSEC-2026-0370 a
  0372, de 2026-10-16). São avisos, não vulnerabilidades.

- **O serviço do Âncora com a sessão.** Hoje o `ancora servir` não sobe sozinho
  no login (pendência do Âncora); até lá, o RemoteID só assina com ele no ar.

## O repositório

O código vive no repositório do RemoteID-linux (`LLawli/RemoteID-linux`), que
ele substitui. A reescrita entrou na `main` em 2026-10-31 (PR #34) por um merge
com dois pais, a v0.3.2 e a história própria da reescrita, com a árvore da
reescrita inteira. O código, as tags e as releases da v0.3.2 ficam onde
estavam; o flatpak-adv-br compila a v0.3.2 pelo commit fixado e não lê a
`main`.
