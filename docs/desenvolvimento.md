# Desenvolvimento

## Dependências

- Rust estável (1.92 ou mais novo).
- GTK 4.18 e libadwaita 1.7, ou mais novos, com os cabeçalhos
  (`gtk4-devel libadwaita-devel` no Fedora). Só para a janela: sem eles,
  `cargo build --no-default-features` constrói o módulo e o `remoteid` sem a
  janela nem o diálogo, com todos os outros subcomandos.
- `appstream`, para validar o metainfo.
- `openssl`, que os testes usam para conferir o `.p7s`.
- `cargo-audit`.
- Para a extensão: o Âncora (`dev.lukakuuhaku.Ancora`) instalado,
  `org.flatpak.Builder`, `org.gnome.Sdk//51` e
  `org.freedesktop.Sdk.Extension.rust-stable//26.08`.

## Gates

```bash
scripts/ci.sh
```

Formatação, clippy com avisos como erro e testes (com e sem a feature
`janela`), `cargo audit` e validação do metainfo. A CI roda o mesmo script, num contêiner Fedora 44, porque o Ubuntu
dos runners traz GTK e libadwaita mais antigos que os do runtime.

## Dependências Rust e o Flatpak

O `flatpak-builder` constrói sem rede. Cada crate do `Cargo.lock` precisa estar
em `cargo-sources.json`, e depois de mexer nas dependências é preciso
regenerar:

```bash
scripts/cargo-sources.py
```

O teste `tests/flatpak.rs` falha enquanto os dois estiverem fora de sincronia.
O script cobre só crates do crates.io; uma dependência git é recusada.

## Paridade com o RemoteID-linux

`tests/paridade.rs` compara o protocolo com fixtures gravadas rodando o
RemoteID-linux v0.3.2, e roda no `scripts/ci.sh` como qualquer teste. Para
regenerar as fixtures, veja [paridade/README.md](../paridade/README.md).

## Servidor falso

O `remoteid-mock` faz o papel da Certisign, para testar tudo sem a conta real.
Os testes do motor o sobem sozinhos; para usar à mão:

```bash
cargo run --bin remoteid-mock          # imprime o endereço; 0 como argumento escolhe a porta
REMOTEID_SERVIDOR=http://127.0.0.1:8799 REMOTEID_HOME=/mnt/dados/caches/remoteid-teste remoteid ...
```

Credenciais: `teste@remoteid.local` / `teste-1234`, PIN `1234`, OTP `123456`.
`POST /_mock/expirar` esquece as sessões abertas, como quando elas vencem.
`REMOTEID_HOME` separa o estado e a chave de teste dos da conta real.

## O módulo PKCS#11 à mão

`tests/modulo.rs` percorre o módulo pela tabela de funções. Para vê-lo num
hospedeiro de verdade, com o `pkcs11-tool` do OpenSC e o servidor falso:

```bash
cargo build
export REMOTEID_HOME=/mnt/dados/caches/remoteid-teste REMOTEID_SERVIDOR=http://127.0.0.1:8799
target/debug/remoteid-mock &
echo teste-1234 | target/debug/remoteid entrar teste@remoteid.local
pkcs11-tool --module target/debug/libremoteid.so -L
pkcs11-tool --module target/debug/libremoteid.so -s -m SHA256-RSA-PKCS -i doc -o doc.sig
```

A assinatura abre o diálogo (`remoteid pedir`, ao lado do `.so`).
`REMOTEID_DIALOGO` troca o executável do diálogo, por exemplo por um roteiro que
responde sozinho: ele recebe o pedido em JSON no stdin (`pedir_senha`,
`pedir_pin`), escreve `{"senha":"…","pin":"…","otp":"…"}` no stdout, só com o
que foi pedido além do OTP, e sai com 0, ou sai com outro código para
desistir.

A senha vai para o chaveiro de quem roda. `REMOTEID_COFRE=nenhum` desliga o
chaveiro (os testes usam); aí o `remoteid entrar` lê o PIN local na segunda
linha da entrada, ou a senha é pedida a cada sessão.

## Diagnóstico

Cada processo grava um JSONL em `<estado>/diagnostico/`, com senha, PIN, OTP
e dados do titular fora e tokens como impressão digital. O arquivo nasce na
primeira linha, que é o evento `inicio` (versão, hospedeiro, runtime,
sistema); quem não tem nada a registrar não deixa arquivo. Ficam 30 dias, até
64 MiB somados (os mais velhos saem primeiro), e um arquivo para em 8 MiB.
Medido nos testes: de 1 a 3 KB por comando de terminal, 13 KB pelo módulo
numa sessão com quatro assinaturas.
`REMOTEID_DIAG_CRU=1` mostra os tokens, para investigar o protocolo na própria
máquina.

No módulo PKCS#11, cada chamada vira um evento `pkcs11` (função, argumentos
que não são segredo, `rv`, `ms`). As de rotina ficam num anel de 64 em memória
e só vão ao disco antes de uma que importa: `C_Login`, `C_Sign*`,
`C_Encrypt*`, qualquer retorno diferente de `CKR_OK` e `CKR_BUFFER_TOO_SMALL`,
ou um `panic`, que vira `CKR_GENERAL_ERROR` com mensagem e local. A sonda do
Âncora, que só lista slots e tokens, não deixa arquivo.

`remoteid diagnostico > remoteid-diagnostico.tar.gz` empacota a pasta inteira
(os JSONL e os relatórios do harness) com um `ambiente.json`.

`remoteid harness` roda o fluxo com a conta já entrada (servidor, conta,
carteira, cadeia e uma assinatura de teste, conferida contra a chave do
certificado e fechada num `.p7s`) e grava um relatório em
`<estado>/diagnostico/harness-<epoch>.txt`, sem senha, PIN, OTP, e-mail nem o
titular. Gasta um código do autenticador quando não há sessão em cache.

## Construir a extensão

```bash
scripts/construir.sh
flatpak run --command=ancora dev.lukakuuhaku.Ancora extensoes
flatpak run --command=/app/extensoes/driver/RemoteID/bin/remoteid dev.lukakuuhaku.Ancora
```

O `construir.sh` exporta para `repo/` e instala de lá, por um remote
`file://` local, como quem instala do remote do projeto; `--repo DIR` só
exporta. O build mora em `.flatpak-builder/`, um link para o SSD de dados. O
segundo comando confere que o Âncora leu o `ancora.toml`; o terceiro abre a
janela dentro do sandbox do Âncora, como o atalho fará.

## Soltar uma versão

A extensão chega a quem usa pelo `bin/publicar` do Âncora, que compila a pasta
`extensoes/`, não a `main`: publique a partir da `main` já com tudo o que a
versão leva. A entrada da versão no metainfo é escrita à mão, e pode estar no
working copy. Depois:

```bash
bin/release 0.5.0              # versão, CHANGELOG, gates, push da main e tag
bin/release 0.5.0 --sem-push   # para no commit local; jj undo desfaz
```

A tag dispara o `.github/workflows/release.yml`, que confere a versão e cria a
release com as notas do CHANGELOG, o código, o `remoteid-x86_64.tar.gz` e o
`remoteid-servidor-x86_64.tar.gz`. Para
refazer a release de uma tag que já existe:
`gh workflow run release.yml -f tag=v0.5.0`.

O tarball sai do `scripts/binario.sh`, que compila no SDK do GNOME 51 e guarda
o resultado em `target/sdk/`. O arquivo tem `bin/remoteid` e
`lib/libremoteid.so` na raiz, e o nome não muda entre versões.

O de servidores sai do `scripts/servidor.sh`: o `remoteid` sem a janela,
ligado estaticamente ao musl no `rust:1.92-alpine` (fora do Alpine, o script
se roda num contêiner), em `target/servidor/`, só com `bin/remoteid`. O script
falha se o programa não sair estático. Vai sem o módulo porque um `.so` musl
não carrega num p11-kit com glibc. Medido em 2026-11-13: o mesmo binário roda
no Rocky 8, no Ubuntu 20.04, no Debian 11 e no Alpine, e o TLS fecha sem
certificados de CA no sistema (as raízes vêm no binário); um build glibc
feito no Debian 11 já não roda no Rocky 8 (pede `GLIBC_2.29`). Contra o
servidor falso, o musl custa cerca de 1 ms a mais por assinatura.
