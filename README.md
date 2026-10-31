# RemoteID para o Âncora

Faz o certificado em nuvem RemoteID da Certisign funcionar no Linux, onde a
Certisign não publica aplicativo: no leitor de PDF, nos navegadores e nos
assinadores que você já usa. É para quem tem certificado RemoteID e precisa
assinar ou entrar com ele (PJe, e-SAJ, Receita) numa máquina Linux.

É uma extensão do [Âncora](https://github.com/LLawli/flatpak-adv-br): instale o
Âncora, depois esta extensão pela tela de extensões dele. Você entra na conta
uma vez; a senha fica no chaveiro do sistema e, ao assinar, só o código do
autenticador é pedido, numa janela no seu desktop. A assinatura acontece no
HSM da Certisign: a chave do certificado nunca esteve na sua máquina.

> **Não é um produto oficial da Certisign.** O protocolo foi reconstruído por
> engenharia reversa do aplicativo oficial de macOS e confirmado com uma conta
> real. Software livre, GPLv3, sem vínculo com a empresa.

Esta é a reescrita do zero do RemoteID-linux, que deixa de ter instalador
próprio e passa a viver dentro do Âncora. A versão anterior, até a v0.3.2, está
no histórico e nas releases deste repositório.

## Instalar

Ainda não há versão publicada. Para construir e instalar a partir do código,
com o Âncora já instalado:

```bash
flatpak install flathub org.gnome.Sdk//51 org.freedesktop.Sdk.Extension.rust-stable//26.08
scripts/construir.sh
```

## Usar

O RemoteID aparece no Âncora: entre na conta pela janela, e os navegadores e
assinadores passam a ver o certificado como um token. O código do autenticador
é pedido na hora de assinar.

Pelo terminal, um `.p7s` destacado de qualquer arquivo, na política AD-RB da
ICP-Brasil:

```bash
R="flatpak run --command=/app/extensoes/driver/RemoteID/bin/remoteid dev.lukakuuhaku.Ancora"
$R assinar < contrato.pdf > contrato.pdf.p7s
```

`--anexar` põe o documento dentro do `.p7s`, `--cru` devolve só a assinatura
RSA, e `--hash <hex>` assina um SHA-256 pronto. O documento entra pela entrada
padrão porque o Âncora não enxerga a pasta pessoal, e o código do autenticador
é pedido na janela do RemoteID. `$R harness` testa o fluxo
e grava um relatório para mandar a quem investiga um problema.

## Vindo da v0.3.2

A v0.3.2 se instalava sozinha, em `~/.local`, e registrava o próprio módulo no
p11-kit. Com as duas instaladas, o certificado aparece duas vezes nos
navegadores. Antes de instalar a extensão, desfaça a antiga com o
`desinstalar.sh` que veio no pacote dela (ou `make desinstalar`, se você a
compilou), e entre na conta de novo pela janela do RemoteID no Âncora: a
v0.3.2 guardava a conta em outro lugar. O código e os pacotes da v0.3.2
continuam na tag e na release `v0.3.2`.

## Para quem vai mexer no código

[docs/arquitetura.md](docs/arquitetura.md) explica as peças e o plano, e
[docs/desenvolvimento.md](docs/desenvolvimento.md) explica como construir e
testar. `scripts/ci.sh` roda todos os gates, os mesmos da CI.

## Licença

GPL-3.0-only. Veja [LICENSE](LICENSE).
