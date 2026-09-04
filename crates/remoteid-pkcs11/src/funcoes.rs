//! As funções Cryptoki que este módulo realmente implementa.
//!
//! Todas são `unsafe extern "C"` porque recebem ponteiros crus do hospedeiro, e
//! todas passam pela macro [`crate::entrada`], que impede um `panic` de
//! atravessar a fronteira FFI.

#![allow(non_snake_case)]

use std::collections::HashMap;

use cryptoki_sys::*;

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
        // O certificado do RemoteID é RSA-2048 e só; não há geração de chave
        // aqui, então mínimo e máximo são o mesmo número.
        *pInfo = CK_MECHANISM_INFO {
            ulMinKeySize: 2048,
            ulMaxKeySize: 2048,
            flags: CKF_SIGN,
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
        // final de `docs/memoria/remoteid-pkcs11-registro-nss.md`.
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
        if pMechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mecanismo = &*pMechanism;
        if !matches!(mecanismo.mechanism, CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS) {
            return CKR_MECHANISM_INVALID;
        }
        // `CKM_RSA_PKCS` não usa parâmetros. Alguns hosts passam ponteiro nulo
        // com `ulParameterLen` zero (o esperado); qualquer outro combo é
        // sintoma de que quem chamou queria PSS ou outra coisa.
        if mecanismo.ulParameterLen != 0 || !mecanismo.pParameter.is_null() {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        // Objeto tem de existir E ser a chave privada. Aceitar o certificado
        // por engano faria o hospedeiro chegar até o `C_Sign` só para receber
        // erro de dados: melhor recusar já.
        let objeto = modulo.token.as_ref().and_then(|t| t.objeto(hKey));
        let Some(objeto) = objeto else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if objeto.atributo(CKA_CLASS).map(|a| a.valor.as_slice())
            != Some(CKO_PRIVATE_KEY.to_ne_bytes().as_slice())
        {
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
        sessao.assinatura = Some(crate::EstadoAssinatura {
            mecanismo: mecanismo.mechanism,
            chave: hKey,
        });
        CKR_OK
    })
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
        if sessao.assinatura.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pulSignatureLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let Some(token) = modulo.token.as_ref() else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        // 256 bytes para chave de 2048 bits (o único tamanho que o RemoteID
        // usa e o único que este módulo publica).
        const N_BYTES: usize = 256;

        // Consulta de tamanho: ainda não consome o estado da assinatura,
        // exatamente como manda a especificação.
        if pSignature.is_null() {
            *pulSignatureLen = N_BYTES as CK_ULONG;
            return CKR_OK;
        }
        if (*pulSignatureLen as usize) < N_BYTES {
            *pulSignatureLen = N_BYTES as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }

        // Só agora a operação é consumida.
        let dados = if ulDataLen == 0 {
            &[][..]
        } else {
            if pData.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            std::slice::from_raw_parts(pData as *const u8, ulDataLen as usize)
        };
        // CKM_RSA_PKCS aceita até `k - 11` bytes (com k = tamanho do módulo);
        // CKM_SHA256_RSA_PKCS não tem esse limite, hasheamos primeiro.

        let mecanismo = sessao
            .assinatura
            .as_ref()
            .expect("conferido acima")
            .mecanismo;
        let assinatura = match assinar(token, mecanismo, dados) {
            Ok(v) => v,
            Err(rv) => return rv,
        };
        // O RSA-2048 sempre devolve 256 bytes: se não deu isto, é bug e o
        // hospedeiro vai rejeitar mais adiante mesmo assim.
        if assinatura.len() != N_BYTES {
            return CKR_FUNCTION_FAILED;
        }

        std::ptr::copy_nonoverlapping(assinatura.as_ptr(), pSignature, N_BYTES);
        *pulSignatureLen = N_BYTES as CK_ULONG;

        // Consumida: uma sessão só pode ter uma assinatura em andamento.
        modulo
            .sessoes
            .get_mut(&hSession)
            .expect("sessão conferida")
            .assinatura = None;
        CKR_OK
    })
}

/// Faz a assinatura de fato. Dois caminhos:
///
/// - **teste** (há `chave_teste` local): assina aqui mesmo, com a chave local.
///   Comportamento inalterado — é o que `p11tool --test-sign` e o Papers em
///   modo de teste exercitam.
/// - **produção** (sem chave local): pede ao app via socket. O digest SHA-256
///   é extraído conforme o mecanismo e o app assina (com a chave real no HSM),
///   cuidando de PIN/OTP, `tokensessao` e `requestHash`.
fn assinar(token: &Token, mecanismo: CK_MECHANISM_TYPE, dados: &[u8]) -> Result<Vec<u8>, CK_RV> {
    match token.chave_teste.as_ref() {
        Some(chave) => assinar_local(chave, mecanismo, dados),
        None => {
            let digest = digest_sha256(mecanismo, dados)?;
            crate::cliente::assinar_pelo_app(&digest)
        }
    }
}

/// Assinatura local com a chave de teste (modo de teste). Inalterado.
fn assinar_local(
    chave: &remoteid_cripto::ChaveInstalacao,
    mecanismo: CK_MECHANISM_TYPE,
    dados: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    match mecanismo {
        CKM_RSA_PKCS => {
            // Quem chama já entregou o bloco final (tipicamente o DigestInfo do
            // hash). O comprimento é limitado a `k - 11` bytes; o gate ficou
            // em `C_Sign`, mas o `sign` do `rsa` também rejeita.
            if dados.len() > 256 - 11 {
                return Err(CKR_DATA_LEN_RANGE);
            }
            chave
                .assinar_pkcs1_v15_cru(dados)
                .map_err(|_| CKR_FUNCTION_FAILED)
        }
        CKM_SHA256_RSA_PKCS => {
            // O módulo hasheia, insere o DigestInfo do SHA-256 e assina — que é
            // exatamente o que a `assinar_digest` faz, com o SHA-256 embutido.
            let hash = remoteid_cripto::sha256(dados);
            chave.assinar_digest(&hash).map_err(|_| CKR_FUNCTION_FAILED)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// O prefixo do `DigestInfo` do SHA-256 (RFC 8017): 19 bytes antes do hash.
const PREFIXO_DIGESTINFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Extrai o digest SHA-256 de 32 bytes que o app espera, conforme o mecanismo.
///
/// O servidor RemoteID só assina SHA-256, então recusamos qualquer outra coisa:
/// - `CKM_SHA256_RSA_PKCS`: `dados` é o conteúdo cru; hasheamos aqui.
/// - `CKM_RSA_PKCS`: o poppler/NSS mandam o `DigestInfo` do SHA-256 (51 bytes);
///   tiramos o prefixo. Alguns hosts mandam o hash cru (32 bytes).
fn digest_sha256(mecanismo: CK_MECHANISM_TYPE, dados: &[u8]) -> Result<[u8; 32], CK_RV> {
    match mecanismo {
        CKM_SHA256_RSA_PKCS => Ok(remoteid_cripto::sha256(dados)),
        CKM_RSA_PKCS => {
            if dados.len() == 51 && dados[..19] == PREFIXO_DIGESTINFO_SHA256 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&dados[19..]);
                Ok(h)
            } else if dados.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(dados);
                Ok(h)
            } else {
                // Não é SHA-256: o RemoteID não sabe assinar isto.
                Err(CKR_DATA_LEN_RANGE)
            }
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
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
