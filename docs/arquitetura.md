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
verdade hoje (a real e a de teste).

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
3. **Motor e servidor falso**: preparar (login, registro do desktop e
   carteira), estado, sessão em cache, assinar, diagnóstico redigido, e o
   servidor RemoteID falso que os testes usam.
4. **Módulo PKCS#11 com o motor dentro e o diálogo de PIN e OTP sob demanda**,
   testados com só o `ancora servir` no ar (nenhuma janela aberta), por
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

- **Um `C_Sign` que espera a pessoa digitar.** O pedido de PIN e OTP segura o
  `C_Sign` por dezenas de segundos dentro do `p11-kit server` do Âncora.
  Conferir na etapa 4 que a supervisão do Âncora (sonda a cada 10 s, com limite
  de 10 s) não toma isso por driver travado, e se o contrato de extensão
  precisa de um campo novo para isso.
- **O serviço do Âncora com a sessão.** Hoje o `ancora servir` não sobe sozinho
  no login (pendência do Âncora); até lá, o RemoteID só assina com ele no ar.

## O repositório

O código vive no repositório do RemoteID-linux (`LLawli/RemoteID-linux`), que
ele substitui. Até a publicação, a reescrita fica no branch `reescrita-ancora`,
com histórico próprio; a `main` continua sendo a v0.3.2. Na etapa 7 ela entra na
`main` por pull request, num commit que troca a árvore inteira, e o histórico,
as tags e as releases da versão anterior ficam onde estão.
