# Como o certificado é exposto ao SO/navegador (e o roadmap do app GTK)

Levantado do app oficial de macOS. É o mapa para o objetivo final: um app GTK no
Linux que expõe o certificado em nuvem RemoteID a navegadores e apps nativos,
como o DesktopID faz no macOS/Windows.

## A arquitetura do app oficial

Três peças:

```
  Navegador (Firefox/Chromium)
        │  PKCS#11 (NSS)
        ▼
  libdesktopID_Provider  (módulo PKCS#11)
        │  socket unix /osesocket   (+ lê identity.xml; lança o app com "open -a" se preciso)
        ▼
  desktopID.app  (daemon)
        │  HTTPS (login → registrar → carteira → tokensessao → requestHash)
        ▼
  RemoteID (remoteidcertisign.com.br)  — assina o hash em nuvem, aprovado por otp/pin
```

1. **O módulo PKCS#11** (`libdesktopID_Provider`) é registrado no NSS de cada
   perfil do navegador (`modutil -add desktopID -libfile <módulo>`, mais a cadeia
   ICP-Brasil via `certutil -A`). O navegador o carrega e vê um "token" com o
   certificado do titular.
   - Implementa a API Cryptoki inteira: `C_GetSlotList`, `C_GetTokenInfo`,
     `C_OpenSession`, `C_FindObjects{Init,,Final}`, `C_GetAttributeValue`,
     `C_SignInit`/`C_Sign`, etc.
   - A assinatura RSA é um **OpenSSL ENGINE próprio** (`certi::signer::CertisignEngine`,
     callbacks `certisignRsaSign`/`certisignRsaPrivEnc`/`certisignRsaPrivDec`): em
     vez de usar uma chave local, o callback **abre o socket e pede a assinatura
     ao daemon**.
   - `C_FindObjects` expõe dois objetos: o **certificado** (`CKO_CERTIFICATE`, o
     X.509 que veio da carteira) e a **chave privada** (`CKO_PRIVATE_KEY`) cujo
     `C_Sign` delega ao daemon.

2. **A ponte** é o socket unix `/osesocket`. O provider lê `identity.xml`
   (`identityCode`/`identityType`) para saber qual instalação, conecta ao socket,
   envia o hash a assinar, e recebe a assinatura. Se o daemon não está rodando,
   ele o inicia (`open -a desktopID.app`, no macOS).

3. **O daemon** (`desktopID.app`) é quem fala com o RemoteID: mantém o estado
   (codigoDesktop, certificado, chave da instalação), atende o socket, e para
   cada pedido de assinatura faz `tokensessao` → `requestHashSessionSignature`
   (pedindo o otp/pin ao usuário pela UI). É exatamente o que o
   o binário `desktopid` já faz em linha de comando.

## Roadmap do app GTK (Linux)

O protocolo com o servidor RemoteID já está todo mapeado (docs/PAYLOADS.md); é o
que o CLI faz. Falta só a camada de exposição ao SO, que é replicável — e o
protocolo interno (daemon ↔ módulo) pode ser **o nosso**, não precisa copiar o
`/osesocket` byte a byte.

1. **Daemon GTK** (equivale ao `desktopID.app`):
   - Reusa a lógica do CLI: login → registrar desktop → carteira →
     `tokensessao(otp)` → `requestHashSessionSignature`.
   - Guarda o estado em disco: chave privada da instalação (PEM 0600),
     codigoDesktop, e o certificado da carteira.
   - UI GTK para login e para pedir o OTP/PIN na hora de assinar.
   - Escuta num socket unix local (o *nosso* protocolo: p.ex. JSON
     `{op:"sign", hash:<b64>, keyId:...}` → `{signature:<b64>}`).

2. **Módulo PKCS#11** (equivale ao `libdesktopID_Provider`):
   - Um `.so` Cryptoki. Não precisa do ENGINE da Certisign; o `C_Sign` chama o
     daemon pelo socket e devolve a assinatura ao navegador.
   - `C_FindObjects` expõe o certificado da carteira (X.509) e o objeto de chave
     privada cujo `C_Sign` delega.
   - Base viável: um módulo fino em C sobre a spec PKCS#11, ou aproveitar
     `p11-kit`/uma lib de esqueleto Cryptoki. Registrar no NSS com o mesmo
     `modutil -add`, e no p11-kit para apps nativos.

3. **Registro/distribuição**:
   - `modutil -add <nome> -libfile <módulo.so> -dbdir <perfil>` em cada perfil de
     Firefox/Chromium, + cadeia ICP-Brasil (mesma dos scripts
     `install-mobileid-to-firefox` do app oficial).
   - Empacotar em Flatpak nos moldes do `flatpak-adv-br` (módulo + registro no
     NSS via preparar.sh / native-messaging).

## O que o CLI entrega para o app GTK

Agora que o motor (`desktopid-core`) assina ponta a ponta (fechou o
`tokensessao`/`requestHash`), ele já é o "motor" do daemon: dado um hash e o
otp/pin, devolve a `signatureBase64`. O app GTK é esse motor + UI + o módulo
PKCS#11 que o expõe ao navegador.
