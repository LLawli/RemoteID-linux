# RemoteID (extensão do Âncora)

Sucessor do `~/Personal/RemoteID-linux`, escrito do zero como extensão de
driver do Âncora (`~/Personal/adv-central`). Arquitetura e plano de etapas em
`docs/arquitetura.md`; construir e testar em `docs/desenvolvimento.md`.

## Memória (ai-memory)

O `.ai-memory.toml` fixa o projeto em `remoteid`. Enquanto a migração não
terminar, toda consulta à memória busca também no escopo do antigo, onde estão
as armadilhas do protocolo e das contas de teste, e no do Âncora, dono do
contrato de extensão:

```
memory_query(query=..., scopes=[
  {workspace: "default", project: "remoteid"},
  {workspace: "default", project: "RemoteID-linux"},
  {workspace: "default", project: "ancora"},
])
```

Escritas vão só para `remoteid`. Armadilha encontrada na memória do antigo que
afeta este projeto ganha página própria aqui, em `gotchas/`, com o fato medido,
a etapa onde ela pega e o caminho da página de origem.

## Regras do projeto

- **O protocolo com a Certisign não muda.** Payloads, endpoints,
  canonicalização, `Bearer` sobre os bytes exatos do corpo, `USER_AGENT`.
  Todo código de protocolo entra com teste de paridade 1:1 contra o
  RemoteID-linux, para requisições e para a leitura das respostas
  (`tests/paridade.rs`). As fixtures em `tests/paridade/` só mudam
  regeneradas pelo `paridade/`, nunca à mão.
- **PIN, OTP e senha nunca** vão para log, teste, fixture ou documentação.
  Fixtures são sintéticas; nada de `.logs/` do antigo entra no repositório.
- Gates: `scripts/ci.sh`, rodado com teto de CPU e memória nesta máquina.
- Build só no SSD de dados (`target/`, `paridade/target/` e
  `.flatpak-builder/` são symlinks para `/mnt/dados/builds/`), nunca em
  `/tmp`. Artefato de debug, build do Flatpak e experimento são apagados
  quando cumprem o propósito; no mínimo ao fechar cada etapa.
- Depois de mudar o `Cargo.lock`, rode `scripts/cargo-sources.py`.
- O ref `dev.lukakuuhaku.Ancora.Driver.RemoteID` é também o id do aplicativo no
  Âncora e não muda. Em outro hospedeiro, o id sai do `FLATPAK_ID`
  (`remoteid::id_do_aplicativo`).
- O `libremoteid.so` não pode depender de GTK: o GTK só entra pelo binário.
- **Assinar não depende da janela aberta.** Só o `ancora servir` publicando o
  driver tem de bastar: o motor mora no módulo, e o PIN e o OTP são pedidos
  por um diálogo aberto sob demanda.
- Testes de extensão instalada rodam na VM `ancora-fedora`
  (`/mnt/dados/caches/vms/ancora-fedora`), não no Flatpak do host, onde
  outras sessões testam o Âncora.
