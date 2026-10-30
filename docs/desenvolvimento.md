# Desenvolvimento

## Dependências

- Rust estável (1.92 ou mais novo).
- GTK 4.18 e libadwaita 1.7, ou mais novos, com os cabeçalhos
  (`gtk4-devel libadwaita-devel` no Fedora).
- `appstream`, para validar o metainfo.
- `cargo-audit`.
- Para a extensão: o Âncora (`dev.lukakuuhaku.Ancora`) instalado,
  `org.flatpak.Builder`, `org.gnome.Sdk//51` e
  `org.freedesktop.Sdk.Extension.rust-stable//26.08`.

## Gates

```bash
scripts/ci.sh
```

Formatação, clippy com avisos como erro, testes, `cargo audit` e validação do
metainfo. A CI roda o mesmo script, num contêiner Fedora 44, porque o Ubuntu
dos runners traz GTK e libadwaita mais antigos que os do runtime.

## Dependências Rust e o Flatpak

O `flatpak-builder` constrói sem rede. Cada crate do `Cargo.lock` precisa estar
em `flatpak/cargo-sources.json`, e depois de mexer nas dependências é preciso
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

Cada execução grava um JSONL em `<estado>/diagnostico/`, os 20 últimos, com
senha, PIN, OTP e dados do titular fora e tokens como impressão digital.
`REMOTEID_DIAG_CRU=1` mostra os tokens, para investigar o protocolo na própria
máquina.

## Construir a extensão

```bash
flatpak run org.flatpak.Builder --user --install --force-clean build-dir flatpak/dev.lukakuuhaku.Ancora.Driver.RemoteID.yml
flatpak run --command=ancora dev.lukakuuhaku.Ancora extensoes
flatpak run --command=/app/extensoes/driver/RemoteID/bin/remoteid dev.lukakuuhaku.Ancora
```

O segundo comando confere que o Âncora leu o `ancora.toml`; o terceiro abre a
janela dentro do sandbox do Âncora, como o atalho fará.
