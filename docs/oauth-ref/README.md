# Fluxo OAuth2/PKCE do RemoteID — REFERÊNCIA (não é o fluxo do CLI)

> Isto é material de **referência**. O `desktopid-cli`/`desktopid-harness` usam o
> fluxo do app desktop (login `usrsenha` → `tokensessao` → `requestHash`), que é
> outro caminho. O fluxo abaixo é o de **login web com certificado** (integração
> gov.br / portais), capturado da página `/api/v0/oauth/authorize`. Guardado só
> porque confirma campos e mostra a arquitetura.

Arquivos: `authorize-page.html` e `authorize-inline.js` (a página e o JS inline).

## A URL de entrada

```
GET https://remoteidcertisign.com.br/api/v0/oauth/authorize
    ?response_type=code
    &client_id=<uuid>
    &scope=single_signature          # há também outros scopes
    &redirect_uri=<url do cliente OAuth, ex.: sso.acesso.gov.br>
    &code_challenge=<PKCE>&code_challenge_method=S256
    &state=<opaco>
```

É OAuth2 Authorization Code + PKCE, igual ao VIDaaS. `scope=single_signature`
indica que dá para autorizar uma assinatura por esse caminho.

## Endpoints (todos sob `/api/v0/oauth/`, exceto onde indicado)

| Endpoint | Método | Papel |
|---|---|---|
| `verify-user?cpf=<cpf>&client_id=<id>` | GET | roteia a conta: retorna `"certisign"`, `"remoteid"` ou legado |
| `authorize` | GET | página de login OAuth (v0); há também `/api/v1/oauth/authorize` |
| `authenticate` | POST | autentica (form-urlencoded); ver campos abaixo |
| `authenticatepush` | POST | inicia aprovação por push |
| `rejectauthenticatepush` | POST | cancela o push (`{request_Id}`) |
| `getcodeauthorization` / `getcodeauthorizationpush` | POST (form) | devolve o `code` de autorização (redireciona ao `redirect_uri`) |

## Roteamento por conta (`verify-user`)

O JS decide o backend a partir da resposta de `verify-user`:

- `"certisign"` → redireciona para **`https://remote-api.certisign.com.br/api/v1/oauth/authorize`** (backend **V2**).
- `"remoteid"`  → segue no `/api/v0/oauth/authorize` com `login_hint=<cpf>`.
- outro         → fluxo legado.

**Observado ao vivo:** o CPF do testador (conta "Certisign - Varejo") roteia para
`"certisign"` — ou seja, no fluxo OAuth ele iria para o backend V2
(`remote-api.certisign.com.br`, que responde). Isso é específico do OAuth; o
login `usrsenha` do fluxo desktop funciona no host V0 normalmente, então o CLI
não muda de host por causa disto. Fica como pista caso o fluxo desktop também
venha a ter uma variante V2 para contas varejo.

## Autenticação (`POST /api/v0/oauth/authenticate`)

- **Content-Type: `application/x-www-form-urlencoded`** (NÃO JSON — diferente do
  fluxo desktop, que é JSON).
- Corpo = os parâmetros OAuth da URL (`client_id`, `scope`, `code_challenge`, …)
  mais, de `getParams()`:
  - `pin` — PIN do certificado
  - `otp` — código TOTP (2FA)  *(id do input é `totp`)*
  - `certificate_id` — id do certificado escolhido
  - `email`
  - `login_hint`/`cpf`
- Resposta traz `oauth_do_login_error` (`"no_error"` em sucesso), `message`, e
  `certificates` (lista para o usuário escolher `certificate_id`).

## O que isto confirma para o nosso fluxo (desktop)

- Os fatores de autorização são os mesmos: **`otp` (TOTP)**, `pin`, `push`.
- Existe seleção de certificado por id (`certificate_id`), análogo ao
  `issue`/`serialNumber` do `tokensessao`.
- Há um backend **V2** (`remote-api.certisign.com.br`) para o qual contas varejo
  são roteadas no OAuth.

Nada aqui substitui o fluxo do CLI; serve de mapa e validação cruzada.
