# DesktopID / RemoteID (Certisign): protocolo levantado do app oficial

Levantado em 31/08/2026 dos instaladores oficiais: macOS
`desktopID_Intel.zip` (versão **2.2.0.1**, build de 19/03/2024) e Windows
`SetupDesktopID.exe` (Inno Setup, build de 02/09/2024). Todas as afirmações
marcadas como **confirmado** foram verificadas contra o servidor de produção; as
marcadas como **inferido** saíram só das literais do binário e ainda não passaram
por uma chamada bem-sucedida.

Os dois binários foram comparados: **os endpoints e a configuração são idênticos**
(seção 9), apesar dos seis meses de diferença entre as builds.

> Os payloads exatos de cada endpoint (campos de request e response) foram
> reconstruídos por disassembly e estão em [PAYLOADS.md](PAYLOADS.md).
> Este documento cobre a arquitetura; aquele, o formato das chamadas.

## 1. O que o DesktopID é (e o que ele não é)

O RemoteID é o certificado A3 em nuvem da Certisign. O DesktopID é o aplicativo
de desktop que **sincroniza** esse certificado com a máquina, para aplicações e
sites que não falam com a nuvem.

Isso é diferente do modelo do VIDaaS (Valid), onde a chave privada nunca sai do
HSM e toda assinatura é uma chamada remota. Aqui os símbolos do binário mostram
`certi::signer::ArchiveRepository` com

    generateKeyPair(...)          loadProtectedKeyPair(...)
    getPrivateKeyPEM()            getRSAPrivateKey()
    signDigest(...)               decryptContentWithPrivateKey(...)
    saveProtectedKeyPairToOstream(senha, ostream)

ou seja: **existe material de chave privada guardado localmente**, protegido por
senha, e a assinatura acontece na máquina. O papel da nuvem é autenticar o
titular, autorizar a instalação e entregar o conteúdo cifrado.

Consequência prática para o Linux: depois do provisionamento, assinar é OpenSSL
local. O trabalho difícil está no registro e na entrega da chave, não na
criptografia.

## 2. Arquitetura do app oficial

```
navegador / app nativo
        │  PKCS#11
        ▼
/usr/local/lib/libdesktopID_Provider.dylib     ← "desktopID PKCS#11 Provider", slot "desktopID (Slot)"
        │  socket unix (osesocket) + spawn de app.app (janela de PIN)
        ▼
/Applications/desktopID.app  (Qt 5.15.10 / QML)
        │  identity.xml + repositório de chaves, em Application Support
        │  HTTPS
        ├──► certinext.certisign.com.br/CertisignerServices/desktop/*   (registro, autorização)
        └──► remoteidcertisign.com.br/api/*                             (login, carteira, assinatura)
```

O provider é registrado no NSS do Firefox pelo script
`Contents/InitScripts/install-mobileid-to-firefox.sh`, que roda
`modutil -add desktopID -libfile <provider>` em cada perfil e importa a cadeia
ICP-Brasil com `certutil -A -t T,T,T`. O nome antigo do módulo era
`MobileID_Desktop`, e o script ainda o remove.

### Por que isso é portável para Linux

O executável principal linka **apenas**: Qt 5.15 (Core, Gui, Widgets, Qml,
Quick, QmlModels, Network), libc++, OpenSSL estático, Boost (`boost::format`,
`boost::algorithm`), e frameworks da Apple para UI e keychain
(AppKit, Foundation, Security, IOKit, DiskArbitration).

Nada do núcleo do protocolo depende de macOS: HTTP é QtNetwork, cripto é
OpenSSL, formatação é Boost. As partes específicas da plataforma são a interface
e o armazenamento no Keychain, ambas substituíveis. Um cliente Linux não precisa
de nenhum binário da Certisign, exatamente como no caso do VIDaaS.

## 3. Bases de URL

Vêm de `/Library/Application Support/desktopID/applicationConfig-2.properties`,
instalado pelo subpacote `br.com.certisign.ApplicationConfig2`:

```properties
certinext.url       = https://certinext.certisign.com.br
certinext.base.name = /CertisignerServices

remoteid.url        = remoteidcertisign.com.br
```

**Confirmado:** os caminhos `/api/...` respondem em `remoteidcertisign.com.br`,
não em `certinext` (lá dão 404). Os caminhos curtos (`/create`, `/push/`, ...)
respondem sob `certinext.certisign.com.br/CertisignerServices/desktop`.

O backend é JBoss-EAP/7 com Undertow, e responde em português.

## 4. Endpoints

Todos extraídos das literais `wchar_t` (UTF-32) do binário. Elas não aparecem em
`strings` comum justamente por serem `std::wstring` — no macOS, `wchar_t` tem 4
bytes, então é preciso `strings -eL`.

### 4.1 Serviço do DesktopID

Base: `https://certinext.certisign.com.br/CertisignerServices/desktop`

| Caminho | Estado |
|---|---|
| `/listHierarchies` | **confirmado**, responde sem autenticação |
| `/create` | **confirmado** (valida `publicKey`) |
| `/requestAuthorization/<code>` | inferido |
| `/isAuthorized/<code>` | inferido |
| `/cancelAuthorization/<code>` | inferido |
| `/isDone/<code>` | inferido |
| `/listCertificates/<code>` | inferido |
| `/maintenanceDevices/<code>` | inferido |
| `/push/<code>` | inferido |

### 4.2 API do RemoteID

Base: `https://remoteidcertisign.com.br`

| Caminho | Papel |
|---|---|
| `POST /api/manager/usuarios/login/usrsenha` | login por usuário e senha; devolve `sessionToken` |
| `GET /api/manager/desktopid/{id}/carteira` | carteira (wallet) de certificados |
| `GET /api/manager/desktopid/{id}/carteira/invalida` | invalida a carteira |
| `GET /api/manager/desktopid/{id}/statusCelular` | estado do pareamento com o celular |
| `GET /api/manager/desktopid/usuario/{1}/organizacao/{2}` | vínculo usuário/organização |
| `POST /api/signature/tokensessao` | token de sessão de assinatura |
| `POST /api/signature/requestHashSessionSignature` | assinatura de hash na sessão |

A autenticação é `Authorization: Bearer <sessionToken>` — as literais `Bearer`,
`Bearer ` e `sessionToken` estão no binário, junto de `application/json`.

**Confirmado:** `POST /api/manager/usuarios/login/usrsenha` com corpo vazio
responde 500 (o caminho existe), enquanto um caminho inventado no mesmo host dá
403/404.

## 5. Payloads

### 5.1 `GET /listHierarchies` — confirmado

Resposta real:

```json
{
  "status": true,
  "hierarchies": [
    {"displayName": "CPF",  "code": "cpf",
     "fields": [{"mask": "999.999.999-99", "regexValidator": "\\d{11}"}]},
    {"displayName": "CNPJ", "code": "cnpj",
     "fields": [{"mask": "99.999.999/9999-99", "regexValidator": "\\d{14}"}]}
  ],
  "futureVersion": {"availableSince": "2019-01-14", "versionString": "2.1.0.2"}
}
```

Hierarquias em produção: `cpf`, `cpfio`, `cnpj`, `sigServices`, `pucminas`,
`anima`, `fundacaobahiana`, `sistemaFiergs`.

Repare que `mask` e `regexValidator` discordam: a máscara é formatada, o regex
espera 11 dígitos crus. O identificador vai **sem pontuação**.

### 5.2 `POST /create` — parcialmente confirmado

O servidor responde 200 mesmo em erro, com o erro no corpo. Foi assim que o
formato do campo da chave foi determinado:

| Corpo enviado | Resposta |
|---|---|
| `{}` | `Nova instalação sem chave pública não suportado` |
| `{"PublicKey": "..."}` | `Nova instalação sem chave pública não suportado` |
| `{"publicKey": "<b64 DER>"}` | `Error sending apns server` |

Ou seja: **o campo é `publicKey` em camelCase, e o valor é o base64 do DER
SubjectPublicKeyInfo** (o corpo do PEM, sem cabeçalho e sem quebras de linha).
Uma chave RSA 2048 gerada na hora é aceita.

A segunda mensagem mostra o passo seguinte do fluxo: o servidor tenta **enviar
um push (APNs) para o celular do titular**. Sem identificação de usuário não há
para quem enviar, e é aí que ele para. Confirmar os campos restantes exige uma
conta RemoteID real.

Campos candidatos, todos presentes como literais no binário:

```
authorizationMode  availableSince  certificate  code  desktopCode  desktopInfo
device  devices  displayName  domainName  expires  fantasyName  field  fields
friendlyName  guid  hash  hierarchies  hierarchy  installation  installationCode
installationName  keyId  keyName  keyReference  keyReferences  lastModified
localName  mask  mobileIdInstallation(s)  operatingSystem  organizationId
organizationName  privateKeyReference  publicKey  regexValidator
remoteIdInstallation(s)  sessionToken  targetUrl  userId  userName
versionString  wallet
```

Modos de autorização, também literais: `push`, `otp`, `pin`, `local`, `mobileId`.

### 5.3 Fluxo completo (inferido a partir do encadeamento acima)

1. `create` com a chave pública da instalação → o servidor devolve um código e
   dispara push para o celular.
2. `requestAuthorization/<code>` inicia a aprovação.
3. `isAuthorized/<code>` em poll, até o titular aprovar no app do celular.
   As classes `FoundDevicesModel::cbUpdateListDeviceWaiting` e
   `updateStatus` mostram que a UI faz exatamente esse poll.
4. `listCertificates/<code>` traz os certificados da carteira.
5. O material da chave, cifrado, é carregado por
   `ArchiveRepository::loadProtectedKeyPair(senha, ...)` e daí em diante
   `signDigest` assina localmente.

## 6. Armazenamento local do app oficial

Em `Application Support`, com o provider PKCS#11 lendo os mesmos arquivos:

- `identity.xml` — identidade da instalação (`identityCode`, `identityType`)
- `osesocket` — socket unix entre o provider e o app
- `proxy.properties` — proxy (`proxy.enable`, `proxy.mode`, `proxy.address.http`,
  `proxy.address.https`, `proxy.bypass`, `proxy.username`, `proxy.password`,
  `proxy.initialAutenticate`)
- `last-version-marker` — controle de "primeira abertura desta versão"

## 6b. Correção: a assinatura em nuvem é remota (disassembly)

A leitura inicial ("a chave desce para a máquina") vale para o certificado A1
em arquivo, via `ArchiveRepository`. Para o certificado **em nuvem** (RemoteID),
o disassembly do fluxo de assinatura mostra o contrário: o cliente manda o hash,
o titular aprova no celular, e o servidor devolve a assinatura pronta. Dois
caminhos, ambos no binário (detalhe de campos em docs/PAYLOADS.md):

- `push` (POST, `{keyName,keyType:RSA,hashAlgorithm,hashContent}`) -> `requestCode`,
  depois `isDone/{requestCode}` faz poll e retorna `signedHash`.
- `tokensessao` -> `requestHashSessionSignature` (API RemoteID, Bearer), que
  retorna `signatureBase64`.

Ou seja, o modelo de nuvem é mais próximo do VIDaaS do que a primeira análise
sugeriu: a chave privada A3 não precisa estar na máquina para assinar.

## 7. O que falta para um cliente Linux completo

1. **Confirmar o payload de `create`** com uma conta RemoteID real. É o único
   bloqueio de verdade; tudo depois dele decorre da resposta.
2. **Formato do repositório de chaves.** `saveProtectedKeyPairToOstream` e
   `loadProtectedKeyPair` recebem senha como `std::wstring`. Descobrir se é
   PKCS#12 padrão ou formato próprio decide se dá para usar OpenSSL puro.
3. **Camada PKCS#11**, se o objetivo for navegador e apps nativos: um módulo
   Cryptoki fino sobre a chave local, registrado no p11-kit. Bem mais simples que
   o caso VIDaaS, porque a chave está na máquina e não exige round-trip de rede
   por assinatura.

## 8. Como isto foi obtido

```sh
curl -O https://drivers.certisign.com.br/DesktopID/MAC/desktopID_Intel.zip
unzip desktopID_Intel.zip && bsdtar -xf desktopID_Intel.pkg    # xar
bsdtar -xf desktopID.app.pkg/Payload                           # cpio+gzip

BIN=desktopID.app/Contents/MacOS/desktopID
strings -a -eL "$BIN"    # <- UTF-32: é aqui que estão os endpoints
llvm-nm "$BIN" | llvm-cxxfilt    # símbolos C++ preservados, nada strippado
```

O QML da interface está num Qt Resource comprimido dentro do binário; um
varredor de blocos zlib recupera os arquivos em texto
(`RemoteIdRegistrationStep1.qml`, `MaintenanceDevices1..4.qml` e outros).

O instalador de Windows é Inno Setup, e `7z` não o abre. `innoextract` resolveu,
rodado num contêiner efêmero para não instalar nada no host:

```sh
podman run --rm -v "$PWD:/w:z" -w /w debian:stable-slim bash -c \
  "apt-get -qq update && apt-get -qq install -y innoextract &&
   innoextract -s -d /w/win-inno /w/SetupDesktopID.exe"
```

## 9. Validação cruzada com o app de Windows

O `desktopID.exe` (5,3 MB, 02/09/2024) traz **exatamente a mesma lista de
endpoints**, e o `applicationConfig-2.properties` instalado em
`commonappdata\desktopID\` é byte a byte o mesmo do macOS. Nenhuma divergência
de protocolo entre as plataformas.

Atenção ao extrair as literais: no Windows `wchar_t` tem **2** bytes, então é
`strings -el`; no macOS são 4 bytes, `strings -eL`.

O binário de Windows revela ainda o nome interno do projeto,
`certinextdesktop`, e que o JSON e o XML são feitos com **jsoncpp** e **pugixml**
(os caminhos de fonte `model/jsoncpp.cpp` e `model/pugixml.cpp` ficaram no
binário).

### A única diferença real é onde a chave vive

| | chave da instalação |
|---|---|
| Windows | CNG/CryptoAPI — a literal `RSAPUBLICBLOB` está no `.exe` |
| macOS | `Security.framework` / Keychain |
| Linux (este CLI) | arquivo PEM com modo 0600 + OpenSSL |

Isso não afeta o protocolo: o que vai para o servidor é o base64 do DER
SubjectPublicKeyInfo nos três casos, e foi confirmado que o servidor aceita uma
chave gerada pelo `openssl` no Linux.

O PKCS#11 do Windows é `C:\Windows\System32\desktopID_Provider.dll`, registrado
no NSS pelo `install-mobileid-to-firefox.bat` — o mesmo `modutil -add desktopID`
do script de macOS, inclusive removendo o antigo `MobileID_Desktop`.
