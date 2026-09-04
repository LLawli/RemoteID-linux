# RemoteID-linux

**Assine documentos com seu certificado em nuvem RemoteID/DesktopID (Certisign)
no Linux.** A Certisign publica aplicativo só para macOS e Windows: em uma
máquina Linux o seu certificado simplesmente não existe. Este projeto resolve
isso.

Com ele o certificado aparece como um token de verdade para o sistema, então
você assina:

- **no visualizador de PDF** (GNOME Papers e qualquer coisa baseada em poppler);
- **no Firefox e no Chromium**, para autenticar em portais que pedem
  certificado digital;
- **pela linha de comando**, inclusive gerando `.p7s` (CAdES-BES) que validador
  ICP-Brasil aceita;
- **em qualquer programa que fale PKCS#11**, porque é isso que o módulo é.

O PIN e o código do autenticador são pedidos numa janela sua, no seu desktop, e
a assinatura acontece no HSM da Certisign — a chave do certificado nunca esteve
na sua máquina e continua não estando.

> **Não é um produto oficial da Certisign.** O protocolo foi reconstruído por
> engenharia reversa do aplicativo oficial de macOS e confirmado com uma conta
> real. Software livre, GPLv3, sem qualquer vínculo com a empresa.

## Antes de tudo: o que foi testado, e o que não foi

Isto importa mais que qualquer outra coisa neste README.

| caminho de autorização | situação |
|---|---|
| **PIN + OTP** (código do autenticador) | **funciona**, confirmado ponta a ponta com conta real: a assinatura devolvida pelo HSM foi verificada contra a chave pública do certificado do titular |
| **push** (aprovar no celular) | **nunca foi testado com uma conta real** |

O caminho `push` existe no aplicativo oficial, foi lido no binário dele e está
implementado aqui com paridade byte a byte com o construtor original — mas
**nenhuma assinatura real jamais passou por ele**. Código que nunca rodou contra
o servidor de verdade é hipótese, não funcionalidade, e é assim que ele deve ser
tratado até que alguém prove o contrário.

**Quer ajudar a tornar o push real?** Se você tem um certificado RemoteID com
aprovação por celular e topa agir como testador, entre em contato:
**contato@lukakuuhaku.dev**. É preciso alguém com uma conta que use esse método;
sem isso o suporte a push continua não existindo na prática.

## Instalação

Precisa de Linux x86_64 ou aarch64.

### Pacote pronto

Baixe da [última release](https://github.com/LLawli/RemoteID-linux/releases/latest)
o pacote da sua arquitetura, confira o checksum, extraia e instale:

```sh
sha256sum -c SHA256SUMS
tar -xzf remoteid-linux-<versão>-x86_64-linux.tar.gz
cd remoteid-linux-<versão>-x86_64-linux
./instalar.sh
```

O `instalar.sh` não pede root: põe tudo em `~/.local`, registra o módulo
PKCS#11 no p11-kit e instala o ícone e o lançador. Para desfazer,
`./desinstalar.sh` — ele preserva o estado da sua conta.

O pacote traz a linha de comando (`remoteid`), o aplicativo gráfico
(`remoteid-app`), o módulo `libremoteid_pkcs11.so`, o ícone e o lançador.

> O aplicativo gráfico precisa de **GTK4 e Libadwaita** instalados no sistema
> (qualquer desktop GNOME atual já tem). A linha de comando e o módulo PKCS#11
> não dependem de nada além do sistema base.

### Compilando

Precisa de Rust 1.82+. A linha de comando e o módulo PKCS#11 não dependem de
mais nada:

```sh
cargo build --release -p remoteid-cli -p remoteid-pkcs11
```

O aplicativo gráfico precisa de GTK4 e Libadwaita instalados
(`libgtk-4-dev` e `libadwaita-1-dev` no Debian/Ubuntu; `gtk4-devel` e
`libadwaita-devel` no Fedora):

```sh
cargo build --release
make instalar      # em ~/.local, sem root; `make desinstalar` desfaz
```

## Como usar

### Uma vez por máquina

```sh
remoteid preparar        # login no portal, registro do desktop e carteira
```

> **O PIN é o do CERTIFICADO**, definido na emissão ou ativação. Não é a senha
> do portal (essa vai no login) nem o código do autenticador.
>
> **O OTP é de uso único e vale poucos segundos.** Gere-o quando for pedido, não
> antes.

### Assinando pela linha de comando

```sh
remoteid assinar --arquivo contrato.pdf      # pergunta PIN e OTP, sem ecoar
remoteid assinar --hash <base64 do SHA-256>  # se o digest já está pronto
cat dados | remoteid assinar                 # ou pela entrada padrão
```

A saída é a assinatura em base64; com `--saida arquivo.sig` saem os 256 bytes
crus.

Para um envelope que um validador ICP-Brasil aceita:

```sh
remoteid assinar --arquivo contrato.pdf --pkcs7 contrato.p7s
openssl cms -verify -inform DER -in contrato.p7s -content contrato.pdf
```

Sai um CAdES-BES destacado, com `signingCertificateV2` — é esse atributo que faz
o validador aceitar. `--anexar` embute o documento no envelope.

### Assinando no Papers, no Firefox e nos outros

Registre o módulo PKCS#11 para o seu usuário (não precisa de root):

```sh
mkdir -p ~/.config/pkcs11/modules
cat > ~/.config/pkcs11/modules/remoteid.module <<EOF
module: /caminho/para/libremoteid_pkcs11.so
EOF
```

Todo consumidor de NSS (Papers, Firefox, Chromium) passa a enxergar o
certificado pelo p11-kit. Confira com:

```sh
p11-kit list-modules | grep -A2 remoteid
```

**O aplicativo precisa estar aberto na hora de assinar.** Quem conversa com a
Certisign e mostra o diálogo de PIN/OTP é ele:

```sh
remoteid-app
```

Sem ele no ar o certificado até aparece na lista do programa (essa parte é lida
do estado local), mas a assinatura falha — não há quem autorize.

## Onde ficam as suas coisas

Em `~/.local/state/remoteid` (ou `$REMOTEID_HOME`), tudo com permissão 0600:

- `installation-key.pem` — a chave privada desta instalação (não é a do
  certificado; essa nunca sai do HSM)
- `state.json` — registro do desktop, certificado do titular, preferências

O diagnóstico fica em `~/.local/state/remoteid/diag/`: um arquivo JSONL por
execução, os 20 últimos. **Senha, PIN e OTP nunca são gravados**; tokens
aparecem só como impressão digital SHA-256. É o material para anexar a um
relatório de bug:

```sh
remoteid diagnostico
```

## Ajudando a testar o protocolo

O `harness` exercita cada passo do protocolo contra o servidor real, classifica
a resposta e gera um relatório dizendo onde parou. Serve para confirmar
comportamento com contas reais, não para o uso diário:

```sh
curl -fsSL https://raw.githubusercontent.com/LLawli/RemoteID-linux/main/install.sh | sh
```

O script pega o binário da última release; se não houver um para a sua máquina,
compila do código-fonte (e, faltando o Rust, explica como instalar e se oferece
para fazê-lo pelo rustup, sem mexer no sistema). Nada é instalado fora do seu
`~/.cache`. Se você já clonou o repositório: `cargo run --release -- harness`.

O relatório sai em `~/Downloads/remoteid-harness-<data>.txt`. **Senha, PIN e OTP
não entram nele**, mas o arquivo identifica o titular do certificado — envie por
canal privado.

## Desenvolvimento

```sh
make check              # testes, clippy e build de release
make teste-integracao   # gate ponta a ponta do módulo PKCS#11 (precisa de opensc)
make teste-local        # servidor RemoteID falso + conta sintética em /tmp
```

O gate de integração carrega o módulo com o `pkcs11-tool` de verdade, assina
contra um servidor falso e confere a assinatura com o `openssl` — inclusive que
PIN e OTP saíram redigidos do diagnóstico. `tools/auditar-segredos.sh` reprova o
repositório se algum segredo escapar para um arquivo versionado.

Como o protocolo foi reconstruído, o que cada campo significa e por que várias
decisões são contraintuitivas está em [docs/PROTOCOLO.md](docs/PROTOCOLO.md),
[docs/PAYLOADS.md](docs/PAYLOADS.md) e
[docs/escopo-migracao.md](docs/escopo-migracao.md). Os scripts de engenharia
reversa estão em [tools/README.md](tools/README.md).

## Licença

GPLv3-only. Ver [LICENSE](LICENSE).
