# Gerador das fixtures de paridade

Roda o código do RemoteID-linux v0.3.2, o que já conversou com o servidor real
da Certisign, e grava em `tests/paridade/` o que ele manda e o que ele lê. O
`tests/paridade.rs` do pacote compara o código novo com essas fixtures, 1:1.

O motor antigo roda de verdade, com o transporte HTTP dele, contra um servidor
local que grava cada requisição crua (linha, cabeçalhos, corpo em bytes) e
devolve respostas prontas. Todos os valores são sintéticos.

| fixture | o que o antigo fez |
|---|---|
| `requisicoes.json` | método, caminho, cabeçalhos e corpo de cada requisição do caminho PIN+OTP |
| `respostas.json` | o que extraiu de cada resposta, ou o erro que deu |
| `classificacao.json` | a regra e a origem de cada mensagem de erro, e se ela invalida a sessão |
| `canonica.json` | a forma canônica e o `Bearer` de corpos que o caminho PIN+OTP não exercita |
| `algoritmo.json` | os tamanhos e nomes que o campo `algorithm` aceita |
| `constantes.json` | URLs, User-Agent e nome da aplicação |
| `cades.json` | o que o montador do `.p7s` manda ao HSM e o envelope que fecha, e os casos que recusa |

`tests/paridade/chave-teste.pem` é uma chave RSA gerada só para isto. Com ela,
o `Bearer` de cada requisição sai igual nos dois lados (o PKCS#1 v1.5 é
determinístico).

## Regenerar

Só quando o corpus mudar. As fixtures nunca são editadas à mão: uma fixture
corrigida para o teste passar deixa de provar paridade.

```bash
cd paridade
cargo run
```

O RemoteID-linux vem do GitHub pela tag `v0.3.2`, e o repositório está privado:
o `.cargo/config.toml` daqui manda o cargo usar o git do sistema, que pega a
credencial do `gh`. Duas execuções seguidas dão os mesmos arquivos.

Fica fora do pacote principal porque as dependências do antigo levariam o
`Cargo.lock` dele de 68 para 205 pacotes, todos no build offline do Flatpak.
