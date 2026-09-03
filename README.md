# RemoteID-linux

Uso do certificado em nuvem **RemoteID / DesktopID** (Certisign) no Linux, onde
não existe aplicativo oficial: a Certisign só publica build para macOS e
Windows.

O protocolo foi reconstruído por decompilação do app oficial de macOS (2.2.0.1)
e **confirmado ao vivo** com uma conta real: em 02/09/2026 o fluxo fechou ponta
a ponta e a assinatura devolvida pelo HSM foi verificada criptograficamente
contra a chave pública do certificado do titular.

```
login → registrar desktop → carteira → tokensessao (pin+otp) → requestHash
                                                        → assinatura RSA-2048
```

Detalhes do protocolo em [docs/PROTOCOLO.md](docs/PROTOCOLO.md) e
[docs/PAYLOADS.md](docs/PAYLOADS.md); o raciocínio e as armadilhas em
[docs/memoria/](docs/memoria/).

## O que tem aqui

| | o quê | para quê |
|---|---|---|
| `crates/remoteid-core` | o **motor** | dado um hash + PIN + OTP, devolve a assinatura |
| `crates/remoteid-cli` | o binário `remoteid` | o motor pela linha de comando, e o harness |
| `tools/ghidra/` | scripts de engenharia reversa | responder "como o app oficial faz X?" |

O motor em Rust é a base do próximo passo: um daemon com UI GTK e um módulo
**PKCS#11** que exponha o certificado ao Firefox, ao Chromium e aos assinadores
de PDF. Roadmap em [docs/ARQUITETURA-SO.md](docs/ARQUITETURA-SO.md).

## Compilar e usar

Precisa só de Rust estável (1.82+). Sem Python, sem OpenSSL, sem dependência de
sistema.

```sh
cargo build --release
./target/release/remoteid --help
```

Fluxo típico, uma vez por máquina:

```sh
remoteid preparar               # login + registro + carteira
```

E para assinar:

```sh
remoteid assinar --arquivo contrato.pdf     # pergunta PIN e OTP, sem ecoar
remoteid assinar --hash <base64 do SHA-256> # se o digest já está pronto
cat dados | remoteid assinar                # ou pela entrada padrão
```

A saída é a assinatura em base64. Com `--saida arquivo.sig` ela sai como os 256
bytes crus.

> **O PIN é o do CERTIFICADO**, definido na emissão ou ativação. Não é a senha
> do portal (essa vai no login) nem o código do autenticador.
>
> **O OTP é de uso único e vale poucos segundos.** Gere-o quando o comando
> pedir, não antes.

### Envelope PKCS#7 (.p7s)

```sh
remoteid assinar --arquivo contrato.pdf --pkcs7 contrato.p7s
openssl cms -verify -inform DER -in contrato.p7s -content contrato.pdf
```

Sai um CAdES-BES destacado, com `contentType`, `messageDigest`, `signingTime` e
`signingCertificateV2` — esse último é o que faz um validador ICP-Brasil aceitar
o arquivo. `--anexar` embute o documento no envelope.

### O que a assinatura crua é (e o que não é)

Sem `--pkcs7`, `assinar` devolve o bloco RSA **cru** de 256 bytes (PKCS#1 v1.5
sobre SHA-256). É de propósito: é o contrato que o `C_Sign` do PKCS#11 tem de
cumprir.

Detalhe que não é intuitivo: no modo `--pkcs7`, o que vai para o HSM **não** é o
hash do documento, e sim o hash dos atributos assinados (que contêm o do
documento). Quem inverte isso produz um `.p7s` que nenhum validador aceita.

## Estado local

Em `~/.local/state/remoteid` (ou `$REMOTEID_HOME`), tudo 0600:

- `installation-key.pem` — a chave privada desta instalação
- `state.json` — `codigoDesktop`, certificado do titular, política de autorização

O log detalhado fica separado, em `~/.local/state/remoteid/diag/`: um
arquivo JSONL por execução, as 20 últimas. Senha, PIN e OTP **nunca** são
gravados; tokens aparecem só como impressão digital. É o material para anexar a
um relatório de bug:

```sh
remoteid diagnostico
```

## Métodos de autorização

O `tokensessao` exige **PIN e OTP juntos** no mesmo request. Não é "um ou
outro": mandar só um devolve `Informe o Pin` ou `Informe o e-Token(Otp)`.

O método é uma **política local**, não algo que o servidor informe. O padrão é
`local`, que é o caminho pin+otp e é onde o app oficial sempre cai. O caminho
`push` (aprovação no celular) existe no código do app e está implementado aqui
com paridade byte a byte com o construtor dele, mas **nunca foi exercitado com
uma conta real**. Por que é assim, e por que push nunca anda junto de pin/otp,
está em
[docs/memoria/desktopid-modo-autorizacao-ghidra.md](docs/memoria/desktopid-modo-autorizacao-ghidra.md).

## Para o testador: rodar com um comando

O `harness` é a ferramenta de **validação do protocolo**: ele exercita cada
passo, classifica a resposta do servidor e gera um relatório dizendo onde parou.
Serve para confirmar o comportamento com contas reais, não para o uso diário.

```sh
curl -fsSL https://raw.githubusercontent.com/LLawli/RemoteID-linux/main/install.sh | sh
```

O script pega o binário pronto da última release; se não houver um para a sua
máquina, compila do código-fonte (e, se faltar o Rust, explica como instalar e
se oferece para fazê-lo pelo rustup, sem mexer no sistema). Nada é instalado
fora do seu `~/.cache`.

Ele pede e-mail e senha do RemoteID, o PIN do certificado e, na hora, o código
do autenticador. No fim gera **um arquivo em `~/Downloads`**
(`remoteid-harness-<data>.txt`). É esse arquivo que precisamos de volta.

Segurança, em uma frase: a senha é digitada localmente e vai só para o servidor
oficial da Certisign. **Senha, PIN e OTP não entram no relatório**, e os tokens
aparecem só como impressão digital — mas o arquivo identifica o titular do
certificado, então envie por canal privado. Quer auditar antes? O código todo
está neste repositório, e o `install.sh` é curto.

Se você clonou o repositório: `cargo run --release -- harness`.

## Testes

```sh
cargo test
```

Os testes de integração sobem um servidor HTTP local com respostas enlatadas e
verificam o fluxo inteiro sem gastar um OTP de conta real — inclusive que o
header `Authorization` de cada operação é mesmo a assinatura RSA da forma
canônica daquele corpo.

## Análise

Os instaladores oficiais ficam em `vendor/` (não versionados). Para refazer a
extração e usar os scripts de Ghidra, ver a seção 8 de
[docs/PROTOCOLO.md](docs/PROTOCOLO.md) e
[tools/README.md](tools/README.md).

## Licença

GPLv3-only. Ver [LICENSE](LICENSE).
