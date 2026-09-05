# Payloads exatos — DesktopID / RemoteID

Reconstruídos por engenharia reversa do binário oficial de macOS 2.2.0.1, não
por tentativa. Método: o app usa jsoncpp (chaves JSON como literais `char*`) e
QtNetwork; desmontei cada função que referencia um endpoint
(`llvm-objdump -d`, delimitando a função pelos `ret`) e resolvi todas as strings
que ela carrega (`lea rip-relative` → `__cstring`/`__const`). A ordem no código
é sempre: **path, campos do request, depois campos lidos do response**. Isso
separa os dois lados. Confirmado ao vivo onde marcado.

Legenda: **REQ** = corpo enviado, **RES** = campos lidos da resposta,
{x} no path = valor interpolado.

## Bases

- Serviço DesktopID: `https://certinext.certisign.com.br/CertisignerServices/desktop`
- API RemoteID: `https://remoteidcertisign.com.br`

O método HTTP não é literal no binário (é enum do QtNetwork). Onde há corpo JSON
é POST; consultas por path são GET. `listHierarchies` (GET) e `create` (POST)
estão confirmados ao vivo.

---

## Fluxo 1 — Registro da instalação (certinext)

### 1. `POST /api/manager/usuarios/login/usrsenha`  (RemoteID, sem auth)
Login que abre tudo. **O token vem no campo `token`, não `sessionToken`.**

- REQ: `{ "email": <str>, "senha": <str> }`  (há também `urlAcesso`, provável)
- RES: `{ "id", "nome", "organizacaoId", "nomeOrganizacao", "token", "message" }`

### 2. `POST /desktop/create`  (certinext) — confirmado ao vivo
- REQ: `{ "installationName", "operationalSystem", "userName", "domainName", "publicKey" }`
  - `operationalSystem` é grafado assim mesmo (não "operatingSystem").
  - `publicKey` = base64 do DER SubjectPublicKeyInfo (confirmado: uma RSA 2048
    do `openssl` é aceita).
  - `userName` = o e-mail do login; `domainName` = domínio/organização.
- RES: `{ "status", "installationCode", "mensagem"|"message" }`
  - Erros observados: "Problema ao criar uma nova instalação no servidor.",
    " Resposta: ", " Erro HTTP: ".

### 3. `POST /desktop/requestAuthorization/{installationCode}`
Dispara o push para o celular. Duas variantes no binário:

- REQ (registro):   `{ "identityCode", "identityType" }`
- REQ (manutenção): `{ "identityCode", "identityType", "tipooperacao", "devices" }`
  - `identityCode` = identificador na hierarquia (ex.: CPF); `identityType` = a
    hierarquia (`cpf`, `cnpj`, ...).
- RES: `{ "status", "desktopRequestCode" }`
  - **`desktopRequestCode` é o código usado nos passos seguintes**, não o
    `installationCode`.

### 4. `GET /desktop/isAuthorized/{desktopRequestCode}`  — poll
Enquanto o titular não aprova no app do celular.

- RES: `{ "status", "isAuthorized" }`  — parar quando `isAuthorized` for true.

### 5. `GET /desktop/listCertificates/{desktopRequestCode}`
Traz os certificados da carteira depois de aprovado. Referencia `SHA256`/`hash`.

- RES: lista de certificados (campo `certificados`/`certificates`).

### Auxiliares do mesmo fluxo
- `POST /desktop/maintenanceDevices/{...}` — REQ `{ identityCode, identityType, desktopRequestCode, devices }` → RES `{ status, message }`
- `GET /desktop/cancelAuthorization/{deviceCode}` → RES `{ status }`
- `GET /desktop/isDone/{requestCode}` — ver Fluxo 2.
- `GET /desktop/listHierarchies` — sem corpo → RES `{ status, message, hierarchies[] }` (confirmado ao vivo).

---

## Fluxo 2 — Assinatura em nuvem (aprovada no celular)

Aqui está a correção importante à análise inicial: para o certificado **em
nuvem**, a assinatura é **remota**. O cliente manda o hash, o titular aprova no
celular, e o servidor devolve a assinatura pronta. A chave privada não desce
para a máquina neste caminho (o `ArchiveRepository`/`signDigest` local é do
certificado A1 em arquivo, um caminho à parte).

Há dois sub-caminhos, ambos no binário:

### 2a. Assinatura via serviço desktop (push → isDone)
- `POST /desktop/push/{desktopRequestCode}`
  - REQ: `{ "keyName", "keyType": "RSA", "hashAlgorithm", "hashContent" }`
    (`hashContent` = hash a assinar, base64)
  - RES: `{ "status", "requestCode" }`  — dispara push de assinatura ao celular.
- `GET /desktop/isDone/{requestCode}`  — poll até aprovar
  - RES: `{ "status", "hashArray", "signedHash" }`  — **`signedHash` é a
    assinatura**. Erros: "Problema ao enviar hash para assinatura. Erro HTTP ",
    "Erro ao enviar push".

### 2b. Assinatura via sessão RemoteID (tokensessao → requestHash)
- `POST /api/signature/tokensessao`  (bearer)
  - REQ: `{ "desktopCode", "pin", "otp", "push", "nomeAplicacaoDesktop", "issue", "serialNumber" }`
    **`pin` e `otp` vão PREENCHIDOS JUNTOS** (confirmado ao vivo em 02/09/2026;
    ver "Métodos de autorização" abaixo).
  - RES: `{ "status", "token", "message" }`  (token da sessão de assinatura)
- `POST /api/signature/requestHashSessionSignature`  (bearer)
  - REQ: `{ "desktopCode", "sessionToken", "issue", "serialNumber", "algorithm",
    "hashArray": [ { "id", "hash" } ] }`
  - RES: `{ "status", "idArray", "signatureBase64" }`  — **`signatureBase64` é a
    assinatura**.
  - **`algorithm` decide o que o HSM faz com `hash`** (sondagem ao vivo de
    05/09/2026, cinco casos numa única sessão; ver a issue #10):

    | `algorithm` | `hash` enviado | o HSM devolve |
    |---|---|---|
    | `"SHA256"` | o hash cru, 32 bytes | DigestInfo(SHA-256) + padding PKCS#1 v1.5 (o caminho de produção original) |
    | `"SHA1"` | o hash cru, 20 bytes | DigestInfo(SHA-1) + padding (honrado por nome; este cliente não usa) |
    | `""` (string vazia, campo PRESENTE) | o bloco pronto, 34 e 51 bytes sondados | **só o padding PKCS#1 v1.5** (modo cru; é o que o módulo oficial manda para `CKM_RSA_PKCS`) |
    | `"MD5"` | o hash cru, 16 bytes | recusado: `{"certificate": null, "idArray": null, "message": "Erro ao gerar assinatura RSA.", "status": false}`, HTTP 200 |

    PKCS#1 v1.5 é determinístico, e a assinatura de `""` + DigestInfo(SHA-256)
    saiu byte a byte igual à de `"SHA256"` + hash: são a mesma chave e as duas
    semânticas acima, sem terceiro comportamento. O modo cru é o que permite
    `MD5withRSA` (o padrão do PJeOffice ao autenticar). Omitir o campo não foi
    testado; o teto de 245 bytes (`k - 11`) é o do PKCS#1, não uma medida do
    servidor. A resposta de sucesso ecoa em `certificate` dados pessoais do
    titular (CPF, e-mail, data de nascimento) em toda assinatura.

### Métodos de autorização (2FA / assinatura / PIN)

A conta define COMO cada uso do certificado é autorizado. O método vem na
estrutura da carteira/instalação, no campo **`AuthorizationMode`** (junto de
`TargetUrl, UserID, UserName, OrganizationID, OrganizationName, DesktopCode,
Wallet`), com valores `push`, `otp`, `pin`, `local`, `mobileId`.

| AuthorizationMode | campo no tokensessao | como o usuário autoriza |
|---|---|---|
| `push` | `"push": true`   | aprova a operação no app da Certisign no celular |
| `otp`  | `"otp": "<código>"` | digita o código do app autenticador (2FA/TOTP) |
| `pin`  | `"pin": "<pin>"`    | digita o PIN do certificado em nuvem |

**Atenção: `pin` e `otp` NÃO são alternativas.** A tabela acima descreve o que
cada campo carrega, não um "escolha um". Numa conta em modo `otp`, o
`tokensessao` só fecha a sessão com **os dois preenchidos no mesmo request**:

| payload enviado | resposta do servidor |
|---|---|
| `pin:""` + otp | `Informe o Pin` |
| sem a chave `pin` + otp | `Informe o Pin` |
| pin + `otp:""` | `Informe o e-Token(Otp)` |
| **pin + otp** | **`Token gerado com sucesso`** |

Isso bate com o binário: a classe que monta o payload é
`desktopid::model::PasswordAndOtpAuthentication` e preenche os dois campos a
partir do mesmo dicionário. O `pin` é o PIN do **certificado em nuvem**,
definido na emissão/ativação; não é a senha do portal nem o código do
autenticador.

Implicação prática: o fluxo `create` → `requestAuthorization` → `isAuthorized`
do serviço `/desktop` é o caminho de **push** (pareamento aprovado no app). Se a
conta está em `otp`/`pin`, esse caminho falha com "Error sending apns server"
(não há push a enviar); a assinatura vai pela sessão RemoteID
(`tokensessao` com o fator → `requestHashSessionSignature`), usando o
`DesktopCode` lido da carteira.

### Formato do certificado na carteira (confirmado ao vivo)

A carteira retorna `{"certificados": [ { "keyName": "<serial>;<issuer DN>", "base64": "<cert X.509 DER>" } ]}`.
O `keyName` é `serialNumber;issuer` (split por `;`): o serial em hex (ex.:
`12CC6B560ECE122AC1047AA7BE71DBC3`) e o DN do emissor (ex.: `CN=AC OAB G3, ...,
O=ICP-Brasil, C=BR`). No tokensessao/requestHash, `serialNumber` = parte antes do
`;`, `issue` = parte depois.

### Fluxo do app NOVO (RemoteID, otp/pin, sem push) — confirmado ao vivo

O `/desktop/create` + push é o app antigo (o push hoje está bugado no Android).
O app novo registra e assina inteiramente pela API RemoteID, com Bearer:

1. `POST /api/manager/usuarios/login/usrsenha` `{email,senha}` → `{token, id, organizacaoId, cpf, ...}`
2. `POST /api/manager/desktopid/usuario/{userId}/organizacao/{orgId}` (Bearer)
   - REQ: `{ "nomeDesktop", "sistemaOperacional", "nomeUsuarioLocal", "dominioRede", "chavePublica" }`
   - RES: `{ "codigoDesktop", "message" }`  ← este é o `desktopCode` da assinatura
3. `POST /api/manager/desktopid/{codigoDesktop}/carteira` (Bearer)  ← **POST**; path = **codigoDesktop** (não o CPF), GET dá 405 Allow: POST. **O corpo é `{"momento": "<unix timestamp em segundos>"}`** (descoberto por decompilação Ghidra) — corpo vazio dá 400. O statusCelular usa o mesmo corpo.
   - RES: `{ "certificados": [ { "certificadoId", "emissorCertificado", "numeroSerieCertificado", ... } ] }`
4. `POST /api/signature/tokensessao` (Bearer)
   - REQ: `{ "desktopCode": <codigoDesktop>, "otp": "<código>", "nomeAplicacaoDesktop", "issue": <emissorCertificado>, "serialNumber": <numeroSerieCertificado> }`
   - RES completa (observada ao vivo): `{ "status", "message", "token", "certificadoId", "emissorCertificado", "numeroSerieCertificado", "usuarioId", "organizacaoId", "tokenOTP", "pin", "email", "cpf" }`
   - `issue`/`serialNumber` vêm do certificado escolhido na carteira (passo 3).
   - Erro observado quando faltam esses campos: "Não existe autorização válida para este token".
5. `POST /api/signature/requestHashSessionSignature` (Bearer)
   - REQ: `{ "desktopCode", "sessionToken": <token do passo 4>, "issue", "serialNumber", "algorithm":"SHA256", "hashArray":[{"id": 0, "hash": "<base64 do digest binário>"}] }`
     O `id` vai como **inteiro** (índice do hash); a resposta devolve `"0"` como
     string. O `algorithm` vem por parâmetro no binário, não é literal:
     `"SHA256"` foi confirmado ao vivo, e `""` (modo cru) também; ver a tabela
     em 2b.
   - RES: `{ "status", "message", "certificate": {...}, "idArray": [{"id", "status", "message", "signatureBase64"}] }`
   - **`signatureBase64` é assinatura RSA CRUA**, não PKCS#7: 256 bytes
     (RSA-2048, PKCS#1 v1.5 sobre SHA-256), verificada com a chave pública do
     próprio certificado. Quem quiser PDF/CAdES monta o PKCS#7 em volta.
   - O `certificate` da resposta traz os dados do titular já parseados
     (`numeroSerie, emissor, validoDe, validoAte, titular, email, cpf, ...`).

### sessionToken (formato)

O `token` do passo 4 não é JWT: é um registro com campos separados por `;`, a
ser tratado como **opaco** (repassado inteiro no passo 5).

```
sessaoAssinatura;<userId>;<issuer DN urlencoded>;<serial>;0;<base64 de um JWT>;<epoch>;<hmac base64url>
```

### Detalhes confirmados por disassembly (Obj-C + C++)

- **chavePublica** no registro (`usuario/{}/organizacao/{}`) é o **PEM completo**:
  a rotina chama `certi::signer::PublicKey::asPEM()`, não o base64 do DER cru.
  Enviar o DER cru provavelmente causava o `ConstraintViolationException` (o
  servidor parseia a chave e grava campos derivados).
- **dominioRede** não pode ser vazio (o binário valida `domainNameLeftBlank`);
  usar o hostname.
- **tokensessao** monta os TRÊS fatores juntos, nesta ordem:
  `desktopCode, pin, otp, push, nomeAplicacaoDesktop, issue, serialNumber`.
  O construtor do caminho otp/pin (`FUN_100058b9e`) preenche **pin e otp lado a
  lado, do mesmo dicionário**, e fixa `push:false`.
- **requestHashSessionSignature**: o `hash` de cada item de `hashArray` é o
  **base64** do digest (a rotina usa `Base64::fromBinaryToBase64`); `algorithm`
  = "SHA256".
- Toda requisição leva `Content-Type: application/json` (NSURLSession); a
  carteira é POST de corpo vazio.

### Pré-processamento: CPF/identityCode vai SÓ com dígitos

As hierarquias do `listHierarchies` trazem `mask` (ex.: `999.999.999-99`) e
`regexValidator` (ex.: `\d{11}`, cnpj `\d{14}`). Testando os regexes reais: o
validador só casa o valor **cru** — com a máscara aplicada nem `fullmatch` nem
`search` passam (os pontos quebram a sequência de `\d`). Ou seja, a máscara é só
da UI (`HierarchyItemModel::refreshResultMask`) e o app **remove a pontuação
antes de enviar**. O CPF que o login devolve já vem cru (`02586270266`). O CLI
normaliza com `only_digits()` qualquer CPF/identityCode digitado.

### statusCelular (consulta de capacidade, NÃO é pré-passo)

`GET /api/manager/desktopid/{cpf}/statusCelular` (Bearer) →
`{ usuarioPossuiCodigoPush, local, message }`. Só informa se a conta tem um
celular pareado para push; não é gate de registro nem de assinatura. Se
`usuarioPossuiCodigoPush` for false, push não vai funcionar e o caminho é
otp/pin. O harness usa isso para sugerir o método.

### Carteira (RemoteID)
- `GET /api/manager/desktopid/{id}/carteira`  (bearer) → RES `{ certificados, message }`

---

## Como o app oficial faz as chamadas (camada de rede)

O app **não usa QtNetwork**: a rede é feita em **Objective-C / NSURLSession**
(imports `_objc_msgSend`, seletores `setHTTPMethod:`, `setHTTPBody:`,
`setValue:forHTTPHeaderField:`). Uma função HTTP central monta cada request e:

- escolhe o método por um enum do objeto request: no disassembly,
  `cmp [req+0x130], 1` → `cmove` entre as NSStrings `"POST"` e `"GET"`
  (1 = POST, senão GET);
- seta **`Content-Type: application/json` em toda requisição** (a string aparece
  uma única vez, na função central);
- serializa o corpo com jsoncpp só quando o endpoint tem campos.

Consequência para a **carteira**: a rotina dela não serializa nenhum campo (só lê
`certificados` da resposta), logo o corpo é **vazio de verdade (0 bytes)**, não
`{}`. Enviar `{}` retorna 400; o certo é `POST` com `Content-Type:
application/json` e corpo vazio.

## Autenticação por ASSINATURA (endpoints de operação) — descoberto por Ghidra

Os endpoints de OPERAÇÃO (carteira, statusCelular, tokensessao,
requestHashSessionSignature) **não usam o JWT do login**. O header é:

```
Authorization: Bearer <base64( RSA_sign( SHA256( canonical(corpo) ) ) )>
```

- Assinado com a **chave privada da instalação** (a mesma do keygen/registro).
- `canonical(corpo)` (rotina `FUN_10002515b`, chaves em ordem alfabética):
  - string → o valor;  número → o número;  null → nada
  - **bool `true` → o NOME DA CHAVE** (não "true");  **bool `false` → nada**
  - array/object → recursão
  Ex.: `{"momento":"123"}` → `"123"`; `{"otp":"1","push":false}` → `"1"`;
  `{"a":true}` → `"a"`.
- Hash SHA256 (`CryptoProcess::digestContent` via `EVP_get_digestbyname`),
  assinatura RSA (macOS usa SecKey; equivale a PKCS#1 v1.5 do digest).
- O `momento` (timestamp) no corpo é o anti-replay: a assinatura cobre o corpo.

Só o **registro** (`/usuario/{userId}/organizacao/{orgId}`) e o **login** usam o
JWT. Enviar o JWT nos endpoints de operação causava `Illegal base64 character 2e`
(o `.` do JWT, que o servidor tentava base64-decodar esperando a assinatura).

> A serialização canônica exata (ordem, bool/null, encoding) ainda é a melhor
> hipótese; pode precisar de ajuste fino contra o servidor.

## Autenticação (login e registro)

- RemoteID (`/api/*`): `Authorization: Bearer <token>` (o `token` do login).
- Serviço desktop (`/desktop/*`): pelo `desktopRequestCode`/`requestCode` no
  path; não usa Bearer nas chamadas confirmadas.

## O que ainda depende de conta real (o harness resolve)

Tudo acima é a estrutura estática. Com uma conta o harness confirma: valores de
`issue`/`serialNumber` (provável ID e serial do certificado escolhido), o que o
servidor exige em `identityType` vs hierarquia, e o formato exato de
`signedHash`/`signatureBase64` (DER? PKCS#7?). São detalhes de valor, não mais
de nome de campo.
