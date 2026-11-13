# RemoteID

Faz o certificado em nuvem RemoteID da Certisign funcionar no Linux, onde a
Certisign não publica aplicativo: no leitor de PDF, nos navegadores, nos
assinadores que você já usa e nos seus próprios programas. É para quem tem
certificado RemoteID e precisa assinar ou entrar com ele (PJe, e-SAJ, Receita)
numa máquina Linux, ou integrar a assinatura a um sistema.

Você entra na conta uma vez; a senha fica no chaveiro do sistema e, ao assinar,
só o código do autenticador é pedido. A assinatura acontece no HSM da
Certisign: a chave do certificado nunca esteve na sua máquina.

> **Não é um produto oficial da Certisign.** O protocolo foi reconstruído por
> engenharia reversa do aplicativo oficial de macOS e confirmado com uma conta
> real. Software livre, GPLv3, sem vínculo com a empresa.

Há quatro jeitos de usar:

- **Como extensão do [Âncora](https://github.com/LLawli/flatpak-adv-br)**, o
  caminho mais simples: o Âncora publica o certificado para os navegadores e
  assinadores, e a janela do RemoteID cuida da conta.
- **Como extensão do [Tessera](https://github.com/pedrohqb/tessera)**, pelo
  [FlatPark](https://flatpark.org): do mesmo jeito, com o botão RemoteID do
  Tessera abrindo a janela.
- **Sem Flatpak**, com o programa e o módulo PKCS#11 da release ou compilados
  do código.
- **Como API**, para um gateway, um webapp ou o backend de um app de celular:
  `remoteid servir` ([docs/servico.md](docs/servico.md)).

Esta é a reescrita do zero do RemoteID-linux. A versão anterior, até a v0.3.2,
está no histórico e nas releases deste repositório.

## Instalar

### No Âncora

Pela tela de extensões do Âncora, ou pelo terminal:

```bash
flatpak remote-add --user --if-not-exists ancora https://flatpak.lukakuuhaku.dev/ancora.flatpakrepo
flatpak install --user ancora dev.lukakuuhaku.Ancora dev.lukakuuhaku.Ancora.Driver.RemoteID
```

Para construir e instalar a partir do código, com o Âncora já instalado:

```bash
flatpak install flathub org.gnome.Sdk//51 org.freedesktop.Sdk.Extension.rust-stable//26.08
scripts/construir.sh
```

### No Tessera, pelo FlatPark

```bash
flatpak remote-add --user --if-not-exists flatpark https://dl.flatpark.org/flatpark.flatpakrepo
flatpak install --user flatpark io.github.pedrohqb.Tessera io.github.pedrohqb.Tessera.Driver.RemoteID
```

O botão RemoteID do Tessera abre a janela, onde você entra na conta.

### Sem Flatpak

Cada release traz dois pacotes:

- `remoteid-servidor-x86_64.tar.gz`, para servidores: o `bin/remoteid` sem a
  janela, estático, que roda em qualquer Linux x86_64 sem depender de nada
  instalado. Traz tudo menos a janela e o módulo PKCS#11; é o que serve o
  `remoteid servir`.
- `remoteid-x86_64.tar.gz`, para o desktop: `bin/remoteid` com a janela e
  `lib/libremoteid.so`, compilados no GNOME 51 (precisa de GTK 4.18 e
  libadwaita 1.7 no sistema).

```bash
curl -LO https://github.com/LLawli/RemoteID-linux/releases/latest/download/remoteid-servidor-x86_64.tar.gz
tar xzf remoteid-servidor-x86_64.tar.gz && ./bin/remoteid ajuda
```

Ou compile:

```bash
cargo build --release                        # com a janela: precisa do GTK 4.18 e da libadwaita 1.7
cargo build --release --no-default-features  # sem GTK: tudo menos a janela e o diálogo
```

Mantenha `remoteid` e `libremoteid.so` juntos (na mesma pasta, ou em `bin/` e
`lib/` lado a lado): o módulo abre o diálogo do código pelo `remoteid` vizinho.
Para os navegadores e assinadores verem o certificado, registre o módulo no
p11-kit:

```bash
mkdir -p ~/.config/pkcs11/modules
echo "module: $PWD/lib/libremoteid.so" > ~/.config/pkcs11/modules/remoteid.module
```

Sem a janela não há diálogo: o módulo assina com a sessão em cache e, quando
ela vence, pergunta ao programa de `REMOTEID_DIALOGO`
([docs/desenvolvimento.md](docs/desenvolvimento.md#o-módulo-pkcs11-à-mão)).

## Usar

No Âncora ou no Tessera, abra o RemoteID e entre na conta pela janela; os
navegadores e assinadores passam a ver o certificado como um token, e o código
do autenticador é pedido na hora de assinar. Sem a janela, entre pelo terminal:

```bash
remoteid entrar voce@exemplo.com   # a senha pelo stdin
```

No Âncora e no Tessera, o programa fica dentro do Flatpak; os exemplos abaixo
usam `$R`, um destes:

```bash
R="flatpak run --command=/app/extensoes/driver/RemoteID/bin/remoteid dev.lukakuuhaku.Ancora"
R="flatpak run --command=/app/lib/tessera/extensions/RemoteID/extra/bin/remoteid io.github.pedrohqb.Tessera"
```

Fora do Flatpak, troque `$R` por `remoteid`. Um `.p7s` destacado de qualquer
arquivo, na política AD-RB da ICP-Brasil:

```bash
$R assinar < contrato.pdf > contrato.pdf.p7s
```

`--anexar` põe o documento dentro do `.p7s`, `--cru` devolve só a assinatura
RSA, `--hash <hex>` assina um SHA-256 pronto e `--certificado <série>` usa um
certificado que não é o ativo. O documento entra pela entrada padrão porque o
sandbox não enxerga a pasta pessoal. O código do autenticador é pedido no
terminal ou, sem ele, na janela do RemoteID.

O que a janela faz também tem comando: `$R estado` mostra a conta e os
certificados (`--json` para outro programa ler), `$R usar <série>` escolhe o
que assina, `$R atualizar` baixa a carteira de novo, `$R reautorizar` faz a
próxima assinatura pedir o código e `$R sair` sai da conta. `$R harness` testa
o fluxo e grava um relatório para mandar a quem investiga um problema.
`$R ajuda` lista todos.

Para integrar o RemoteID a outro programa, `$R servir` fala JSON por linha no
stdin e stdout, ou num socket só seu com `--socket <caminho>`, e pede o código
do autenticador a quem chama. O protocolo está em
[docs/servico.md](docs/servico.md). Ele não abre porta de rede: expor a
assinatura para fora da máquina, com autenticação e TLS, é papel de quem o
integra.

Quando algo dá errado, `$R diagnostico > remoteid-diagnostico.tar.gz` junta os
registros dos últimos 30 dias num arquivo para anexar ao relato. Ele não traz
senha, PIN, OTP nem os dados do titular, mas identifica a conta: envie por um
canal privado.

## Sites que usam TLS 1.3

Entrar num site com o certificado só funciona em TLS 1.2. O TLS 1.3 exige uma
assinatura RSA-PSS, e o HSM da Certisign só assina em PKCS#1 v1.5: o limite é
do serviço, e o aplicativo oficial de Windows esbarra nele também. Assinar
documentos não é afetado.

No Firefox, a página de erro mostra `SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT`,
mesmo em site que também aceita TLS 1.2, porque o Firefox não recua sozinho.
Para esses sites, abra `about:config` e mude `security.tls.version.max` para
`3`. A opção vale para todos os sites do perfil, então use um perfil só para
isso (`firefox -P`). Em site que só aceita TLS 1.3 não há contorno: o erro
passa a ser `SSL_ERROR_PROTOCOL_VERSION_ALERT`.

## Vindo da v0.3.2

A v0.3.2 se instalava sozinha, em `~/.local`, e registrava o próprio módulo no
p11-kit. Com as duas instaladas, o certificado aparece duas vezes nos
navegadores. Antes de instalar a extensão, desfaça a antiga com o
`desinstalar.sh` que veio no pacote dela (ou `make desinstalar`, se você a
compilou), e entre na conta de novo: a v0.3.2 guardava a conta em outro
lugar. O código e os pacotes da v0.3.2
continuam na tag e na release `v0.3.2`.

## Para quem vai mexer no código

[docs/arquitetura.md](docs/arquitetura.md) explica as peças e o plano, e
[docs/desenvolvimento.md](docs/desenvolvimento.md) explica como construir e
testar. `scripts/ci.sh` roda todos os gates, os mesmos da CI.
[docs/engenharia-reversa/](docs/engenharia-reversa/README.md) tem o protocolo
da Certisign como ele foi levantado dos aplicativos oficiais.

## Licença

GPL-3.0-only. Veja [LICENSE](LICENSE).
