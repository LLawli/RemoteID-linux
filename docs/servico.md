# A API (`remoteid servir`)

Para quem integra o RemoteID num outro programa: um gateway HTTP, um webapp
interno, o backend de um app de celular. Tudo o que a janela faz está aqui,
sem GTK, e quem chama pede o código do autenticador à pessoa do jeito dele.

```bash
remoteid servir                              # no stdin e no stdout
remoteid servir --socket "$XDG_RUNTIME_DIR/remoteid.sock"
```

Com `--socket`, o socket Unix nasce com permissão `0600` (só o dono conecta),
cada conexão é uma conversa independente, e um socket velho no caminho é
trocado; outro tipo de arquivo ali não é apagado. O caminho de um socket Unix
tem no máximo 107 bytes.

Não há HTTP nem rede: autenticar clientes remotos, TLS e escopo por origem são
do gateway que expõe isto para fora.

## Formato

Uma linha JSON por mensagem, nos dois sentidos. Cada pedido tem um `id`
(qualquer valor JSON, devolvido igual) e um `op`. Cada pedido recebe uma
resposta, na ordem:

```json
{"id": 1, "ok": <resultado>}
{"id": 1, "erro": {"tipo": "cancelado", "mensagem": "Cancelado"}}
```

`tipo` é estável e serve para decidir; `mensagem` é para a pessoa ler e pode
trazer o texto do servidor. Os tipos vêm do motor (`rede`, `servidor http=…`,
`nao_preparado: …`, `cancelado`, `pin_bloqueado`, `bloco_invalido`, …) e do
serviço: `pedido_invalido` (JSON, `op` ou campos errados) e `ocupado` (um
pedido de outro `id` enquanto uma assinatura espera os fatores).

## Operações

| `op` | campos | `ok` |
|---|---|---|
| `estado` | | a [visão](#a-visão) |
| `atualizar` | | a visão, depois de baixar a carteira e o estado do celular |
| `entrar` | `email`, `senha`, `pin` (opcional) | `{"chaveiro": bool, "pin": bool}` |
| `usar` | `certificado`: chave ou série | a visão |
| `assinar` | ver abaixo | `{"assinatura": "<base64>"}` |
| `reautorizar` | | `null`; a próxima assinatura pede os fatores |
| `sair` | | `null`; esquece a conta, a carteira e a senha neste computador |

`entrar` registra esta máquina e baixa a carteira. A senha vai para o chaveiro
do sistema; sem chaveiro (`"chaveiro": false`), o `pin` de 4 a 6 dígitos a
cifra no disco, e as assinaturas passam a pedir esse PIN em vez da senha.

`assinar`:

| campo | |
|---|---|
| `formato` | `destacado` (padrão): `.p7s` sem o documento, na política AD-RB; `anexado`: `.p7s` com o documento; `cru`: a assinatura RSA PKCS#1 v1.5 do SHA-256 ou do `digest_info` |
| `hash` | o SHA-256 do documento em hexadecimal (não serve para `anexado`) |
| `documento` | o documento em base64, no lugar do `hash` |
| `digest_info` | só no `cru`: o DigestInfo pronto em base64, no lugar do `hash` e do `documento`, para um resumo de outro algoritmo (o TLS 1.2 pede SHA-384 e SHA-512, por exemplo) |
| `certificado` | chave ou série; sem ele, o certificado ativo |

## Os fatores

Com a sessão em cache válida, `assinar` responde direto. Quando ela não vale
mais, o serviço pergunta antes de responder:

```json
{"id": "a", "pedir": {"titular": "FULANO:00000000000", "recusa": null,
                      "pedir_senha": false, "pedir_pin": true, "senha_guardada": false}}
```

e espera, no mesmo `id`, uma destas:

```json
{"id": "a", "fatores": {"otp": "123456", "pin": "1234"}}
{"id": "a", "cancelar": true}
```

- `otp` vai sempre; `pin` só com `pedir_pin`, `senha` só com `pedir_senha`.
- `recusa` é a mensagem da tentativa anterior: o servidor recusou, ou o PIN
  local errou. O servidor não diz se o errado foi a senha ou o OTP, então
  depois de uma recusa ele pede a senha de novo. Com `senha_guardada`, omitir
  `senha` mantém a que está guardada, que nunca sai pelo canal.
- Até três tentativas por assinatura; depois o erro sobe.
- Enquanto espera, um pedido com outro `id` recebe `ocupado`. Fechar a
  conexão desiste da assinatura.

## A visão

```json
{
  "preparado": true,
  "conta": {"email": "…", "nome": "…"},
  "computador": "…",
  "celular_pareado": false,
  "certificados": [{
    "chave": "<série>;<emissor>", "titular": "…", "tipo": "e-CPF",
    "documento": "CPF 000.000.000-00", "emissor": "…", "serie": "…",
    "validade": 1790000000, "dias_restantes": 300, "ativo": true,
    "sessao": {"aberta": true, "ate": 1763050000},
    "cadeia": ["AC …", "AC Raiz …"],
    "certificado": "<DER em base64>"
  }]
}
```

Fora da conta, `conta` é `null` e `certificados` vem vazio. `certificado` é o
DER do certificado, para quem o expõe como token; é `null` quando a carteira
não o trouxe. `sessao.ate` é
`null` quando não dá para saber até quando a sessão vale.

## Segredos

A senha, o PIN, o OTP e o documento só passam pela memória e pelo canal.
O diagnóstico do serviço (`terminal servir` nos registros) não traz nenhum
deles, e `tests/servico.rs` confere isso.

## Por que stdio e socket Unix

Medido em 2026-11-13, binário release contra o servidor falso, 40 rodadas:

| caminho | `estado` | `assinar` com sessão em cache |
|---|---|---|
| um `remoteid` por chamada | 1,8 ms | 6,7 ms |
| socket, conexão aberta | 0,2 ms | 4,2 ms |
| socket, conexão nova por assinatura | | 5,7 ms |

A diferença some diante da ida à Certisign. O que decide é que só a conversa
deixa quem chama responder o OTP no meio da assinatura, e que a conexão aberta
guarda a senha aberta pelo PIN local até fechar, como o módulo faz por
processo. A linha de comando continua valendo para scripts, com o diálogo
trocado por `REMOTEID_DIALOGO`.
