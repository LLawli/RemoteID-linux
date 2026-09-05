//! As funções Cryptoki que este módulo realmente implementa.
//!
//! Todas são `unsafe extern "C"` porque recebem ponteiros crus do hospedeiro, e
//! todas passam pela macro [`crate::entrada`], que impede um `panic` de
//! atravessar a fronteira FFI.

#![allow(non_snake_case)]

use std::collections::HashMap;

use cryptoki_sys::*;

use remoteid_protocolo_servidor::algoritmo::Algoritmo;

use crate::objetos::Objeto;
use crate::token::{Token, ID_SLOT};
use crate::{entrada, trava, Modulo};

/// O valor que a especificação manda pôr em `ulValueLen` quando o atributo não
/// existe, e em campos de `CK_TOKEN_INFO` que o token não sabe informar.
const INDISPONIVEL: CK_ULONG = CK_ULONG::MAX;

/// Versão deste módulo, informada como `libraryVersion` e `firmwareVersion`.
const VERSAO: CK_VERSION = CK_VERSION { major: 0, minor: 1 };

/// Copia `texto` num campo de tamanho fixo do Cryptoki.
///
/// Os campos de texto do Cryptoki são preenchidos com **espaço**, não com NUL, e
/// não são terminados. Terminar com NUL faz ferramenta séria (`p11tool`,
/// `certutil`) mostrar lixo depois do nome, porque ela imprime o campo inteiro.
fn preencher(destino: &mut [u8], texto: &str) {
    destino.fill(b' ');
    let bytes = texto.as_bytes();
    let n = bytes.len().min(destino.len());
    destino[..n].copy_from_slice(&bytes[..n]);
}

// ---------------------------------------------------------------------------
// Ciclo de vida
// ---------------------------------------------------------------------------

/// # Safety
/// `pInitArgs` é `NULL` ou um `CK_C_INITIALIZE_ARGS` válido.
pub unsafe extern "C" fn C_Initialize(pInitArgs: *mut std::ffi::c_void) -> CK_RV {
    entrada!({
        if !pInitArgs.is_null() {
            let args = &*(pInitArgs as *const CK_C_INITIALIZE_ARGS);
            if !args.pReserved.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            // Os callbacks de mutex do hospedeiro são ignorados de propósito:
            // este módulo se tranca sozinho com um `Mutex` do Rust, então é
            // seguro sob qualquer combinação de flags de locking.
        }

        let mut guarda = trava();
        if guarda.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }

        // Um `state.json` ilegível vira "sem token", não erro de inicialização.
        // Falhar aqui derrubaria o carregamento do módulo para todo consumidor
        // de NSS da máquina — Firefox e Chromium inclusive — por causa de um
        // arquivo nosso.
        let token = Token::carregar().ok().flatten();

        *guarda = Some(Modulo {
            token,
            sessoes: HashMap::new(),
            proximo_handle: 1,
            logado: false,
        });
        CKR_OK
    })
}

/// # Safety
/// `pReserved` tem de ser `NULL`, como manda a especificação.
pub unsafe extern "C" fn C_Finalize(pReserved: *mut std::ffi::c_void) -> CK_RV {
    entrada!({
        if !pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut guarda = trava();
        if guarda.is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        *guarda = None;
        CKR_OK
    })
}

/// # Safety
/// `pInfo` tem de apontar para um `CK_INFO` gravável.
pub unsafe extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    entrada!({
        if trava().is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let info = &mut *pInfo;
        info.cryptokiVersion = CK_VERSION {
            major: 2,
            minor: 40,
        };
        info.flags = 0;
        info.libraryVersion = VERSAO;
        preencher(&mut info.manufacturerID, "RemoteID-linux");
        preencher(
            &mut info.libraryDescription,
            "RemoteID (Certisign) em nuvem",
        );
        CKR_OK
    })
}

// ---------------------------------------------------------------------------
// Slots e token
// ---------------------------------------------------------------------------

/// # Safety
/// `pulCount` tem de ser válido; `pSlotList`, ou nulo, ou com espaço para
/// `*pulCount` slots.
pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if pulCount.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // O slot é fixo e sempre existe; o que varia é haver token dentro dele.
        // Quem pede só slots com token e ainda não rodou `remoteid preparar`
        // recebe uma lista vazia, que é a resposta honesta.
        let slots: &[CK_SLOT_ID] = if tokenPresent == CK_TRUE && modulo.token.is_none() {
            &[]
        } else {
            &[ID_SLOT]
        };

        if pSlotList.is_null() {
            // Primeira passada: o chamador só quer saber o tamanho.
            *pulCount = slots.len() as CK_ULONG;
            return CKR_OK;
        }
        if (*pulCount as usize) < slots.len() {
            *pulCount = slots.len() as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(slots.as_ptr(), pSlotList, slots.len());
        *pulCount = slots.len() as CK_ULONG;
        CKR_OK
    })
}

/// # Safety
/// `pInfo` tem de apontar para um `CK_SLOT_INFO` gravável.
pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let info = &mut *pInfo;
        preencher(
            &mut info.slotDescription,
            "RemoteID Certisign (certificado em nuvem)",
        );
        preencher(&mut info.manufacturerID, "Certisign");
        // Sem CKF_HW_SLOT: o HSM é hardware, mas fica do outro lado da rede.
        // Anunciar hardware local faria o hospedeiro prometer ao usuário coisas
        // que só valem para leitor de cartão (presença física, remoção).
        info.flags = if modulo.token.is_some() {
            CKF_TOKEN_PRESENT
        } else {
            0
        };
        info.hardwareVersion = VERSAO;
        info.firmwareVersion = VERSAO;
        CKR_OK
    })
}

/// # Safety
/// `pInfo` tem de apontar para um `CK_TOKEN_INFO` gravável.
pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        let Some(token) = modulo.token.as_ref() else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let info = &mut *pInfo;
        preencher(&mut info.label, "RemoteID Certisign");
        preencher(&mut info.manufacturerID, "Certisign");
        preencher(&mut info.model, "RemoteID");
        // O campo tem 16 caracteres e a série do ICP-Brasil tem 32 dígitos hex:
        // fica o FIM dela, que é a parte que varia entre certificados do mesmo
        // titular. Serve para o humano distinguir tokens, não para casar dados.
        let serie = &token.serie[token.serie.len().saturating_sub(16)..];
        preencher(&mut info.serialNumber, serie);

        // Bits do token. **Este módulo NÃO exige login**, e isso é uma decisão,
        // não um esquecimento (ver [[remoteid-pkcs11-c-sign]], CORRIGIDO):
        //
        // - **`CKF_TOKEN_INITIALIZED`** — o token existe e é usável.
        // - **`CKF_WRITE_PROTECTED`** — não dá para criar objeto: `CKO_CERTIFICATE`
        //   e `CKO_PRIVATE_KEY` vêm do nosso estado, não do hospedeiro.
        //
        // NÃO ligamos `CKF_LOGIN_REQUIRED` nem `CKF_USER_PIN_INITIALIZED`. O
        // módulo não tem PIN próprio: a autenticação REAL (PIN do certificado +
        // OTP) acontece no APP, no `C_Sign`, não aqui. Anunciar login exigido
        // fazia o NSS/poppler tentar autenticar o token com a senha do
        // hospedeiro e recusar ("Password was not accepted") ANTES de chamar
        // `C_Login`, em loop — foi o bug do Papers pedir PIN 6x sem assinar. Sem
        // esses bits, o hospedeiro vai direto ao `C_SignInit`/`C_Sign`, e é o
        // diálogo do app que pede PIN/OTP. (O `C_Login` continua existindo como
        // no-op para hosts que insistam em chamá-lo.)
        info.flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;

        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
        info.ulSessionCount = modulo.sessoes.len() as CK_ULONG;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        // Faixa de PIN. NÃO pode ser 0: o NSS valida o comprimento da senha
        // contra `ulMaxPinLen` ANTES de chamar `C_Login` — com máximo 0, toda
        // senha não-vazia é recusada sem sequer tentar, e o hospedeiro reporta
        // "Password was not accepted" e repete o prompt em loop (foi o bug do
        // Papers pedir PIN 6x sem assinar). O PIN real do certificado vai ao
        // app, não valida aqui; então anunciamos uma faixa permissiva.
        info.ulMinPinLen = 1;
        info.ulMaxPinLen = 255;
        info.ulTotalPublicMemory = INDISPONIVEL;
        info.ulFreePublicMemory = INDISPONIVEL;
        info.ulTotalPrivateMemory = INDISPONIVEL;
        info.ulFreePrivateMemory = INDISPONIVEL;
        info.hardwareVersion = VERSAO;
        info.firmwareVersion = VERSAO;
        // Sem CKF_CLOCK_ON_TOKEN, o campo é ignorado, mas tem de estar em
        // branco — não em zeros — como todo campo de texto do Cryptoki.
        preencher(&mut info.utcTime, "");
        CKR_OK
    })
}

/// Os mecanismos do token.
///
/// `CKM_RSA_PKCS` descreve o que o HSM da Certisign faz, e está confirmado ao
/// vivo: RSA-2048, PKCS#1 v1.5, sobre um digest que o cliente manda pronto. O
/// `C_Sign` correspondente ainda não existe (fatia seguinte) e devolve
/// `CKR_FUNCTION_NOT_SUPPORTED`; anunciar o mecanismo desde já é o que permite
/// verificar que o hospedeiro escolhe este, e não outro.
///
/// # Safety
/// `pulCount` válido; `pMechanismList`, nulo ou com espaço para `*pulCount`.
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: *mut CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        if modulo.token.is_none() {
            return CKR_TOKEN_NOT_PRESENT;
        }
        if pulCount.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mecanismos = [CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS];
        if pMechanismList.is_null() {
            *pulCount = mecanismos.len() as CK_ULONG;
            return CKR_OK;
        }
        if (*pulCount as usize) < mecanismos.len() {
            *pulCount = mecanismos.len() as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(mecanismos.as_ptr(), pMechanismList, mecanismos.len());
        *pulCount = mecanismos.len() as CK_ULONG;
        CKR_OK
    })
}

/// # Safety
/// `pInfo` tem de apontar para um `CK_MECHANISM_INFO` gravável.
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        if modulo.token.is_none() {
            return CKR_TOKEN_NOT_PRESENT;
        }
        if !matches!(type_, CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS) {
            return CKR_MECHANISM_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // `CKM_RSA_PKCS` anuncia `CKF_ENCRYPT` além de `CKF_SIGN`, e isto é uma
        // divergência DELIBERADA do módulo oficial (que é sign-only, `0x0801`).
        // Motivo: desde o JDK-8176837 (11.0.6) o SunPKCS11 só registra o
        // `Cipher.RSA/ECB/PKCS1Padding` de um token se o mecanismo anunciar
        // `CKF_ENCRYPT`, e esse `Cipher` é a ÚNICA porta JCA para RSA cru
        // (`NONEwithRSA` não existe no SunPKCS11). Sem ele o signer4j do
        // PJeOffice cai num provedor de software e falha ao autenticar. O
        // `Cipher` em `ENCRYPT_MODE` com a chave PRIVADA vira `C_SignInit` +
        // `C_Sign`, que já existem; o `C_Encrypt` de verdade só cifra com a
        // pública. Sem `CKF_DECRYPT`: não há como decifrar sem o HSM. Ver a
        // issue #10.
        //
        // O certificado do RemoteID é RSA-2048 e só; não há geração de chave
        // aqui, então mínimo e máximo são o mesmo número.
        let flags = match type_ {
            CKM_RSA_PKCS => CKF_SIGN | CKF_ENCRYPT,
            _ => CKF_SIGN,
        };
        *pInfo = CK_MECHANISM_INFO {
            ulMinKeySize: remoteid_cripto::KEY_BITS as CK_ULONG,
            ulMaxKeySize: remoteid_cripto::KEY_BITS as CK_ULONG,
            flags,
        };
        CKR_OK
    })
}

// ---------------------------------------------------------------------------
// Sessões
// ---------------------------------------------------------------------------

/// # Safety
/// `phSession` tem de apontar para um `CK_SESSION_HANDLE` gravável.
pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: *mut std::ffi::c_void,
    _Notify: CK_NOTIFY,
    phSession: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        if modulo.token.is_none() {
            return CKR_TOKEN_NOT_PRESENT;
        }
        if phSession.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // A especificação reserva o bit para uma sessão "paralela" que nunca
        // existiu; o valor legal é sempre ligado.
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        // O token é só de leitura (CKF_WRITE_PROTECTED): não há como criar
        // objeto nele, então prometer sessão R/W seria mentira.
        if flags & CKF_RW_SESSION != 0 {
            return CKR_TOKEN_WRITE_PROTECTED;
        }
        *phSession = modulo.nova_sessao(flags);
        CKR_OK
    })
}

pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        match modulo.sessoes.remove(&hSession) {
            Some(_) => CKR_OK,
            None => CKR_SESSION_HANDLE_INVALID,
        }
    })
}

pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        modulo.sessoes.clear();
        CKR_OK
    })
}

/// # Safety
/// `pInfo` tem de apontar para um `CK_SESSION_INFO` gravável.
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: *mut CK_SESSION_INFO,
) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        *pInfo = CK_SESSION_INFO {
            slotID: ID_SLOT,
            // O estado TEM de refletir o login: depois do `C_Login`, o NSS chama
            // `C_GetSessionInfo` para CONFIRMAR que a autenticação pegou. Se
            // continuássemos reportando `CKS_RO_PUBLIC_SESSION`, o NSS concluiria
            // que a senha não foi aceita e pediria o PIN de novo, em loop (foi o
            // bug dos "6 prompts" no Papers). Token somente-leitura → variantes
            // RO. (O `p11tool`/GnuTLS não checa isto; o NSS sim.)
            state: if modulo.logado {
                CKS_RO_USER_FUNCTIONS
            } else {
                CKS_RO_PUBLIC_SESSION
            },
            flags: sessao.flags,
            ulDeviceError: 0,
        };
        CKR_OK
    })
}

// ---------------------------------------------------------------------------
// Objetos
// ---------------------------------------------------------------------------

/// Lê o template de busca que o hospedeiro passou.
///
/// # Safety
/// `pTemplate` tem de apontar para `ulCount` `CK_ATTRIBUTE` válidos.
unsafe fn ler_gabarito(
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, CK_RV> {
    let mut gabarito = Vec::with_capacity(ulCount as usize);
    for i in 0..ulCount as usize {
        let attr = &*pTemplate.add(i);
        if attr.ulValueLen == INDISPONIVEL {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let valor = if attr.pValue.is_null() || attr.ulValueLen == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize).to_vec()
        };
        gabarito.push((attr.type_, valor));
    }
    Ok(gabarito)
}

/// # Safety
/// `pTemplate` tem de apontar para `ulCount` `CK_ATTRIBUTE` válidos, ou ser nulo
/// com `ulCount` zero.
pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if modulo.sessoes[&hSession].busca.is_some() {
            return CKR_OPERATION_ACTIVE;
        }
        if pTemplate.is_null() && ulCount != 0 {
            return CKR_ARGUMENTS_BAD;
        }

        let gabarito = if ulCount == 0 {
            Vec::new()
        } else {
            match ler_gabarito(pTemplate, ulCount) {
                Ok(g) => g,
                Err(rv) => return rv,
            }
        };

        // Sem token, a busca é legítima e o resultado é vazio: é o que o NSS
        // espera ao varrer um slot sem token. Todos os objetos são "públicos"
        // (`CKA_PRIVATE = false`), porque o módulo não gate por login — a
        // autenticação é do app, no C_Sign.
        let achados = modulo
            .token
            .as_ref()
            .map(|t| t.buscar(&gabarito))
            .unwrap_or_default();
        modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida acima")
            .busca = Some(achados);
        CKR_OK
    })
}

/// # Safety
/// `phObject` tem de comportar `ulMaxObjectCount` handles; `pulObjectCount` tem
/// de ser gravável.
pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(fila) = sessao.busca.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if pulObjectCount.is_null() || (phObject.is_null() && ulMaxObjectCount != 0) {
            return CKR_ARGUMENTS_BAD;
        }

        // A busca é entregue em pedaços, e o hospedeiro chama até vir zero.
        let n = fila.len().min(ulMaxObjectCount as usize);
        for (i, h) in fila.drain(..n).enumerate() {
            *phObject.add(i) = h;
        }
        *pulObjectCount = n as CK_ULONG;
        CKR_OK
    })
}

pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        match sessao.busca.take() {
            Some(_) => CKR_OK,
            None => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
}

/// Copia atributos do objeto para o template do hospedeiro.
///
/// Duas passadas, como manda a especificação: com `pValue` nulo o chamador só
/// quer o tamanho; com buffer, recebe o valor. E o erro é por atributo, não pela
/// chamada: os atributos que existem são copiados mesmo quando um outro falta, e
/// o `ulValueLen` do que faltou vira `CK_UNAVAILABLE_INFORMATION`. Abortar na
/// primeira falta faria o hospedeiro não receber nada por perguntar um atributo
/// a mais.
///
/// # Safety
/// `pTemplate` tem de apontar para `ulCount` `CK_ATTRIBUTE` válidos.
pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    entrada!({
        let guarda = trava();
        let Some(modulo) = guarda.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let objeto = modulo.token.as_ref().and_then(|t| t.objeto(hObject));
        let Some(objeto) = objeto else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        if pTemplate.is_null() && ulCount != 0 {
            return CKR_ARGUMENTS_BAD;
        }
        copiar_atributos(objeto, pTemplate, ulCount)
    })
}

/// # Safety
/// Vale o contrato de [`C_GetAttributeValue`].
unsafe fn copiar_atributos(
    objeto: &Objeto,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    let mut rv = CKR_OK;
    for i in 0..ulCount as usize {
        let attr = &mut *pTemplate.add(i);
        // Sensível = `n`/`d`/... da chave privada. A especificação manda
        // devolver `CKA_SENSITIVE` e sinalizar por atributo, não invalidar a
        // chamada. Isto vem ANTES do `atributo(...)` porque `CKA_VALUE` existe
        // como atributo no objeto certificado, mas para a chave é sensível.
        if objeto.e_sensivel(attr.type_) {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_ATTRIBUTE_SENSITIVE;
            continue;
        }
        let Some(valor) = objeto.atributo(attr.type_).map(|a| &a.valor) else {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        };
        if attr.pValue.is_null() {
            attr.ulValueLen = valor.len() as CK_ULONG;
            continue;
        }
        if (attr.ulValueLen as usize) < valor.len() {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_BUFFER_TOO_SMALL;
            continue;
        }
        std::ptr::copy_nonoverlapping(valor.as_ptr(), attr.pValue as *mut u8, valor.len());
        attr.ulValueLen = valor.len() as CK_ULONG;
    }
    rv
}

// ---------------------------------------------------------------------------
// Login e assinatura
// ---------------------------------------------------------------------------

/// # Safety
/// `pPin`, se não nulo, tem de ser um buffer com `ulPinLen` bytes.
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    _pPin: *mut CK_UTF8CHAR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        // SO (security officer) e Context-Specific não fazem sentido aqui: o
        // token é somente leitura e não tem PIN administrativo.
        if userType != CKU_USER {
            return CKR_USER_TYPE_INVALID;
        }
        if modulo.logado {
            return CKR_USER_ALREADY_LOGGED_IN;
        }

        // Em modo de teste (que é o único modo que existe hoje), aceito
        // qualquer PIN. É deliberado: a validação de PIN não é o que este
        // módulo prova. Quando o daemon com UI entrar, o PIN e o OTP vão pelo
        // canal do daemon, não pelo `C_Login`. Ver a decisão em aberto no
        // final de [[remoteid-pkcs11-registro-nss]].
        modulo.logado = true;
        CKR_OK
    })
}

pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if !modulo.logado {
            return CKR_USER_NOT_LOGGED_IN;
        }
        modulo.logado = false;
        CKR_OK
    })
}

/// Lê o mecanismo que o hospedeiro pediu, aceitando só os de `permitidos`.
///
/// Nenhum mecanismo deste módulo usa parâmetros. Alguns hosts passam ponteiro
/// nulo com `ulParameterLen` zero (o esperado); qualquer outro combo é sintoma
/// de que quem chamou queria PSS ou OAEP, e aí é melhor recusar já.
///
/// # Safety
/// `pMechanism` tem de ser nulo ou apontar para um `CK_MECHANISM` válido.
unsafe fn ler_mecanismo(
    pMechanism: *mut CK_MECHANISM,
    permitidos: &[CK_MECHANISM_TYPE],
) -> Result<CK_MECHANISM_TYPE, CK_RV> {
    if pMechanism.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mecanismo = &*pMechanism;
    if !permitidos.contains(&mecanismo.mechanism) {
        return Err(CKR_MECHANISM_INVALID);
    }
    if mecanismo.ulParameterLen != 0 || !mecanismo.pParameter.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    Ok(mecanismo.mechanism)
}

/// A `CKA_CLASS` de um objeto do token.
fn classe(objeto: &Objeto) -> Option<CK_OBJECT_CLASS> {
    let valor = &objeto.atributo(CKA_CLASS)?.valor;
    Some(CK_OBJECT_CLASS::from_ne_bytes(
        valor.as_slice().try_into().ok()?,
    ))
}

/// # Safety
/// `pMechanism` tem de apontar para um `CK_MECHANISM` válido.
pub unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let mecanismo = match ler_mecanismo(pMechanism, &[CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS]) {
            Ok(m) => m,
            Err(rv) => return rv,
        };

        // Objeto tem de existir E ser a chave privada. Aceitar o certificado
        // por engano faria o hospedeiro chegar até o `C_Sign` só para receber
        // erro de dados: melhor recusar já.
        let objeto = modulo.token.as_ref().and_then(|t| t.objeto(hKey));
        let Some(objeto) = objeto else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if classe(objeto) != Some(CKO_PRIVATE_KEY) {
            return CKR_KEY_HANDLE_INVALID;
        }
        // Sem gate de login: o módulo não faz autenticação (o app faz, no
        // `C_Sign`). Não exigimos `C_Login` para iniciar a assinatura.

        let sessao = modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida acima");
        if sessao.assinatura.is_some() {
            return CKR_OPERATION_ACTIVE;
        }
        sessao.assinatura = Some(crate::EstadoAssinatura::novo(mecanismo, hKey));
        CKR_OK
    })
}
/// Tamanho de tudo o que sai de uma operação RSA deste módulo (assinatura e
/// cifra): o do módulo da chave, 256 bytes para RSA-2048, que é o único
/// tamanho que o RemoteID emite e que este módulo publica.
const N_BYTES_BLOCO: usize = remoteid_cripto::KEY_BYTES;

/// A parte do protocolo de saída que `C_Sign`, `C_SignFinal` e `C_Encrypt`
/// têm IGUAL.
///
/// O Cryptoki manda responder só o tamanho quando o buffer vem nulo, e recusar
/// quando vem pequeno — e nos dois casos a operação continua ATIVA, para o
/// hospedeiro chamar de novo com espaço. Errar isso faz o host perder a
/// assinatura no meio.
///
/// `Err(rv)` quer dizer "já respondi, retorne isto sem tocar no estado".
unsafe fn conferir_buffer_de_saida(
    pSaida: *mut CK_BYTE,
    pulSaidaLen: *mut CK_ULONG,
) -> Result<(), CK_RV> {
    if pulSaidaLen.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if pSaida.is_null() {
        *pulSaidaLen = N_BYTES_BLOCO as CK_ULONG;
        return Err(CKR_OK);
    }
    if (*pulSaidaLen as usize) < N_BYTES_BLOCO {
        *pulSaidaLen = N_BYTES_BLOCO as CK_ULONG;
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    Ok(())
}

/// Copia um bloco RSA pronto para o buffer do hospedeiro, que
/// [`conferir_buffer_de_saida`] já garantiu ter espaço.
///
/// # Safety
/// `pSaida` tem de apontar para pelo menos `N_BYTES_BLOCO` bytes graváveis e
/// `pulSaidaLen` tem de ser gravável.
unsafe fn entregar_bloco(bloco: &[u8], pSaida: *mut CK_BYTE, pulSaidaLen: *mut CK_ULONG) -> CK_RV {
    // O RSA-2048 sempre devolve 256 bytes: se não deu isto, é bug e o
    // hospedeiro vai rejeitar mais adiante mesmo assim.
    if bloco.len() != N_BYTES_BLOCO {
        return CKR_FUNCTION_FAILED;
    }
    std::ptr::copy_nonoverlapping(bloco.as_ptr(), pSaida, N_BYTES_BLOCO);
    *pulSaidaLen = N_BYTES_BLOCO as CK_ULONG;
    CKR_OK
}

/// Assina `dados` e entrega no buffer do hospedeiro.
///
/// NÃO mexe no estado da sessão: quem chama decide quando a operação acaba,
/// porque a regra é diferente entre os dois caminhos.
unsafe fn assinar_para_buffer(
    token: &Token,
    mecanismo: CK_MECHANISM_TYPE,
    dados: &[u8],
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    match assinar(token, mecanismo, dados) {
        Ok(assinatura) => entregar_bloco(&assinatura, pSignature, pulSignatureLen),
        Err(rv) => rv,
    }
}

/// Lê um bloco que o hospedeiro passou como ponteiro + comprimento.
///
/// Comprimento zero é chamada legítima (o `C_SignUpdate` recebe isso), e aí o
/// ponteiro pode ser nulo sem que seja erro.
unsafe fn bloco_do_host<'a>(p: *mut CK_BYTE, n: CK_ULONG) -> Result<&'a [u8], CK_RV> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(std::slice::from_raw_parts(p as *const u8, n as usize))
}

/// Assinatura de uma parte só (o que o poppler faz ao assinar PDF).
///
/// # Safety
/// `pData` tem de ser um buffer com `ulDataLen` bytes; `pSignature` — nulo ou
/// buffer com `*pulSignatureLen` bytes; `pulSignatureLen`, gravável.
pub unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(estado) = sessao.assinatura.as_ref() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let mecanismo = estado.mecanismo;

        // Consulta de tamanho e buffer pequeno NÃO consomem a operação.
        if let Err(rv) = conferir_buffer_de_saida(pSignature, pulSignatureLen) {
            return rv;
        }

        let Some(token) = modulo.token.as_ref() else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        // CKM_RSA_PKCS aceita até `k - 11` bytes (com k = tamanho do módulo);
        // CKM_SHA256_RSA_PKCS não tem esse limite, hasheamos primeiro.
        let dados = match bloco_do_host(pData, ulDataLen) {
            Ok(d) => d,
            Err(rv) => return rv,
        };
        let rv = assinar_para_buffer(token, mecanismo, dados, pSignature, pulSignatureLen);

        // Consumida: uma sessão só pode ter uma assinatura em andamento.
        modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida")
            .assinatura = None;
        rv
    })
}

/// Junta mais um pedaço do que será assinado (assinatura em FLUXO).
///
/// Existe porque quem assina em fluxo nunca chama `C_Sign`: o BouncyCastle
/// escreve o documento num `SignatureUpdatingOutputStream`, que vira
/// `C_SignInit` → `C_SignUpdate`(n) → `C_SignFinal`. Sem isto, o PJeOffice
/// recebe `CKR_FUNCTION_NOT_SUPPORTED` no primeiro `update` e não assina.
///
/// # Safety
/// `pPart` tem de apontar para `ulPartLen` bytes válidos, ou ser nulo com
/// comprimento zero.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: *mut CK_BYTE,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        // O estado é POR SESSÃO: `C_SignUpdate` sem `C_SignInit` antes não é
        // erro de argumento, é operação não iniciada.
        let Some(estado) = sessao.assinatura.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let pedaco = match bloco_do_host(pPart, ulPartLen) {
            Ok(d) => d,
            Err(rv) => return rv,
        };
        estado.acumular(pedaco);
        CKR_OK
    })
}

/// Fecha a assinatura em fluxo: assina tudo o que o `C_SignUpdate` juntou.
///
/// Sobre o acumulado faz exatamente o que o `C_Sign` faz sobre o bloco único —
/// é o mesmo `assinar_para_buffer`, para os dois caminhos não divergirem.
///
/// # Safety
/// `pSignature`/`pulSignatureLen` seguem o protocolo de duas passadas do
/// Cryptoki, igual ao `C_Sign`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(estado) = sessao.assinatura.as_ref() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let mecanismo = estado.mecanismo;

        // Igual ao `C_Sign`: consulta de tamanho e buffer pequeno deixam a
        // operação ativa, para o hospedeiro voltar com espaço.
        if let Err(rv) = conferir_buffer_de_saida(pSignature, pulSignatureLen) {
            return rv;
        }

        let Some(token) = modulo.token.as_ref() else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        // Cópia proposital: o acumulado sai da mesma estrutura que é limpa logo
        // abaixo, e assinar empresta o token.
        let dados = estado.acumulado().to_vec();
        let rv = assinar_para_buffer(token, mecanismo, &dados, pSignature, pulSignatureLen);

        // A operação acaba aqui, tenha dado certo ou não: a especificação diz
        // que depois do `C_SignFinal` (ou de um erro) a sessão volta ao normal,
        // e um segundo `C_SignFinal` é `CKR_OPERATION_NOT_INITIALIZED`.
        modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida")
            .assinatura = None;
        rv
    })
}

/// O que cada mecanismo faz com os bytes do hospedeiro, ANTES de a chave (local
/// ou no HSM) entrar. É a semântica do Cryptoki, igual nos dois caminhos:
///
/// - `CKM_RSA_PKCS`: os bytes JÁ SÃO o bloco final (tipicamente o DigestInfo
///   de um hash, mas podem ser qualquer coisa de até `k - 11` bytes), e a chave
///   só aplica o padding PKCS#1 v1.5. É o modo cru: o servidor faz isso com
///   `algorithm: ""`, e é o que o módulo oficial manda.
/// - `CKM_SHA256_RSA_PKCS`: os bytes são o conteúdo; o módulo hasheia aqui e a
///   chave embrulha o hash em DigestInfo(SHA-256) e aplica o padding. É o
///   `algorithm: "SHA256"` do servidor.
///
/// Devolve o algoritmo do servidor e os bytes que vão para a chave.
fn preparar_bloco(
    mecanismo: CK_MECHANISM_TYPE,
    dados: &[u8],
) -> Result<(Algoritmo, Vec<u8>), CK_RV> {
    match mecanismo {
        CKM_RSA_PKCS => {
            if dados.len() > remoteid_cripto::MAX_BLOCO_PKCS1_V15 {
                return Err(CKR_DATA_LEN_RANGE);
            }
            Ok((Algoritmo::Cru, dados.to_vec()))
        }
        CKM_SHA256_RSA_PKCS => Ok((Algoritmo::Sha256, remoteid_cripto::sha256(dados).to_vec())),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Faz a assinatura de fato. Dois caminhos, com a MESMA preparação
/// ([`preparar_bloco`]), para nunca divergirem:
///
/// - **teste** (há `chave_teste` local): assina aqui mesmo, com a chave local.
///   É o que `p11tool --test-sign`, o gate de integração em modo local e o
///   Papers em modo de teste exercitam.
/// - **produção** (sem chave local): pede ao app via socket, com o algoritmo e
///   os bytes preparados. O app assina com a chave real no HSM, cuidando de
///   PIN/OTP, `tokensessao` e `requestHash`.
///
/// Antes do modo cru, o `CKM_RSA_PKCS` em produção desmontava o DigestInfo de
/// SHA-256 (51 bytes) e mandava só o hash, recusando o resto com
/// `CKR_DATA_LEN_RANGE`. O bloco agora vai inteiro, seja qual for o hash
/// dentro dele: é assim que o `DigestInfo(MD5)` do PJeOffice chega ao servidor.
fn assinar(token: &Token, mecanismo: CK_MECHANISM_TYPE, dados: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let (algoritmo, bloco) = preparar_bloco(mecanismo, dados)?;
    match token.chave_teste.as_ref() {
        Some(chave) => assinar_local(chave, algoritmo, &bloco),
        None => crate::cliente::assinar_pelo_app(algoritmo, &bloco),
    }
}

/// Assinatura local com a chave de teste: reproduz o que o HSM faz em cada
/// modo, para o gate local valer como prova do caminho de produção.
fn assinar_local(
    chave: &remoteid_cripto::ChaveInstalacao,
    algoritmo: Algoritmo,
    bloco: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    match algoritmo {
        Algoritmo::Cru => chave.assinar_pkcs1_v15_cru(bloco),
        Algoritmo::Sha256 => chave.assinar_digest(bloco),
    }
    .map_err(|_| CKR_FUNCTION_FAILED)
}
// ---------------------------------------------------------------------------
// Cifra (só com a chave pública)
// ---------------------------------------------------------------------------

/// Inicia uma cifra PKCS#1 v1.5 com a chave PÚBLICA do certificado.
///
/// Existe pela especificação: o token anuncia `CKF_ENCRYPT` em `CKM_RSA_PKCS`
/// (ver `C_GetMechanismInfo` para o porquê), e um token que anuncia cifra tem
/// de cifrar com a pública. A chave privada é recusada com
/// `CKR_KEY_FUNCTION_NOT_PERMITTED`: cifrar com a privada não é uma operação
/// do PKCS#11 (o que o SunPKCS11 faz com `Cipher` + chave privada é
/// `C_SignInit`/`C_Sign`, e nunca chega aqui). Nada passa pelo socket nem pede
/// PIN.
///
/// # Safety
/// `pMechanism` tem de apontar para um `CK_MECHANISM` válido.
pub unsafe extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        // Só o cru: `CKM_SHA256_RSA_PKCS` é mecanismo de assinatura e não cifra.
        if let Err(rv) = ler_mecanismo(pMechanism, &[CKM_RSA_PKCS]) {
            return rv;
        }

        let objeto = modulo.token.as_ref().and_then(|t| t.objeto(hKey));
        let Some(objeto) = objeto else {
            return CKR_KEY_HANDLE_INVALID;
        };
        match classe(objeto) {
            Some(CKO_PUBLIC_KEY) => {}
            // É uma chave, mas não cifra: o código específico deixa o
            // hospedeiro distinguir "handle errado" de "operação proibida".
            Some(CKO_PRIVATE_KEY) => return CKR_KEY_FUNCTION_NOT_PERMITTED,
            _ => return CKR_KEY_HANDLE_INVALID,
        }

        let sessao = modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida acima");
        if sessao.cifra.is_some() {
            return CKR_OPERATION_ACTIVE;
        }
        sessao.cifra = Some(crate::EstadoCifra { chave: hKey });
        CKR_OK
    })
}

/// Cifra de uma parte só: `CKM_RSA_PKCS` é single-part por definição, então
/// `C_EncryptUpdate`/`C_EncryptFinal` continuam stubs.
///
/// Mesmo protocolo de duas passadas do `C_Sign` (consulta de tamanho e buffer
/// pequeno deixam a operação ativa); qualquer outro resultado a consome.
///
/// # Safety
/// `pData` tem de ser um buffer com `ulDataLen` bytes; `pEncryptedData` — nulo
/// ou buffer com `*pulEncryptedDataLen` bytes; `pulEncryptedDataLen`, gravável.
pub unsafe extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pEncryptedData: *mut CK_BYTE,
    pulEncryptedDataLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava();
        let Some(modulo) = guarda.as_mut() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if sessao.cifra.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }

        if let Err(rv) = conferir_buffer_de_saida(pEncryptedData, pulEncryptedDataLen) {
            return rv;
        }

        let Some(token) = modulo.token.as_ref() else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        let rv = match bloco_do_host(pData, ulDataLen) {
            Ok(dados) => match cifrar(token, dados) {
                Ok(cifrado) => entregar_bloco(&cifrado, pEncryptedData, pulEncryptedDataLen),
                Err(rv) => rv,
            },
            Err(rv) => rv,
        };

        modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida")
            .cifra = None;
        rv
    })
}

/// Cifra local com a pública do certificado. Puro: nem socket, nem PIN.
fn cifrar(token: &Token, dados: &[u8]) -> Result<Vec<u8>, CK_RV> {
    if dados.len() > remoteid_cripto::MAX_BLOCO_PKCS1_V15 {
        return Err(CKR_DATA_LEN_RANGE);
    }
    // Sem pública não haveria objeto `CKO_PUBLIC_KEY` e o `C_EncryptInit` já
    // teria recusado o handle; chegar aqui sem ela é bug.
    let publica = token.publica.as_ref().ok_or(CKR_FUNCTION_FAILED)?;
    remoteid_cripto::cifrar_pkcs1_v15(publica, dados).map_err(|_| CKR_FUNCTION_FAILED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campo_de_texto_e_preenchido_com_espaco_e_nao_com_nul() {
        let mut campo = [0u8; 8];
        preencher(&mut campo, "abc");
        assert_eq!(&campo, b"abc     ");
    }

    #[test]
    fn texto_maior_que_o_campo_e_truncado_sem_estourar() {
        let mut campo = [0u8; 4];
        preencher(&mut campo, "abcdefgh");
        assert_eq!(&campo, b"abcd");
    }
}
