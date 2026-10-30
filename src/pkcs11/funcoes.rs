//! As funções Cryptoki que o token faz de fato.
//!
//! Todas recebem ponteiros crus do hospedeiro e passam por [`entrada`]. O
//! corpo inteiro de cada uma é a conversa com esses ponteiros, por isso o
//! `unsafe` vale para a função toda e não bloco a bloco.

#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use cryptoki_sys::*;
use rsa::Pkcs1v15Encrypt;

use super::objetos::Objeto;
use super::token::{ID_SLOT, Token};
use super::{MODULO, MOTOR, Modulo, Operacao, entrada, trava};
use crate::caminhos::{self, Caminhos};
use crate::cripto::sha256;
use crate::diagnostico::Diagnostico;
use crate::motor::{Erro, Motor};
use crate::pedido::Dialogo;
use crate::protocolo::classificacao::Origem;
use crate::protocolo::resposta::Erro as ErroProtocolo;
use crate::protocolo::{Algoritmo, Certificado};
use crate::transporte::{Http, TEMPO_LIMITE};

/// O que a especificação põe em `ulValueLen` quando o atributo não existe, e
/// nos campos de `CK_TOKEN_INFO` que o token não sabe.
const INDISPONIVEL: CK_ULONG = CK_UNAVAILABLE_INFORMATION;

const VERSAO: CK_VERSION = CK_VERSION { major: 0, minor: 1 };

/// O tamanho da chave dos certificados do RemoteID. Não há outro.
const BITS_CHAVE: CK_ULONG = 2048;

const MECANISMOS: [CK_MECHANISM_TYPE; 2] = [CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS];

/// Copia `texto` num campo de tamanho fixo. Os campos de texto do Cryptoki
/// são completados com espaço e não terminam em NUL: o `p11tool` e o
/// `certutil` imprimem o campo inteiro.
fn preencher(destino: &mut [u8], texto: &str) {
    destino.fill(b' ');
    let n = texto.len().min(destino.len());
    destino[..n].copy_from_slice(&texto.as_bytes()[..n]);
}

/// Responde uma lista em duas passadas, como a especificação manda: com a
/// lista nula, só o tamanho.
unsafe fn entregar_lista<T: Copy>(itens: &[T], lista: *mut T, contagem: *mut CK_ULONG) -> CK_RV {
    if contagem.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let pedido = *contagem as usize;
    *contagem = itens.len() as CK_ULONG;
    if lista.is_null() {
        return CKR_OK;
    }
    if pedido < itens.len() {
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(itens.as_ptr(), lista, itens.len());
    CKR_OK
}

/// O módulo inicializado, ou o erro que a especificação manda.
macro_rules! modulo {
    ($guarda:ident) => {
        match $guarda.as_mut() {
            Some(m) => m,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        }
    };
}

fn conferir_slot(slot: CK_SLOT_ID) -> Result<(), CK_RV> {
    if slot == ID_SLOT {
        Ok(())
    } else {
        Err(CKR_SLOT_ID_INVALID)
    }
}

// Ciclo de vida

pub(super) unsafe extern "C" fn C_Initialize(pInitArgs: *mut c_void) -> CK_RV {
    entrada!({
        if !pInitArgs.is_null() {
            let args = &*(pInitArgs as *const CK_C_INITIALIZE_ARGS);
            if !args.pReserved.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            // Os callbacks de mutex do hospedeiro ficam sem uso: o módulo se
            // tranca sozinho, e é seguro com qualquer combinação deles.
        }
        let mut guarda = trava(&MODULO);
        if guarda.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        *guarda = Some(Modulo::abrir(Caminhos::do_ambiente().estado()));
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_Finalize(pReserved: *mut c_void) -> CK_RV {
    entrada!({
        if !pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut guarda = trava(&MODULO);
        if guarda.take().is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        *trava(&MOTOR) = None;
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    entrada!({
        if trava(&MODULO).is_none() {
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
        preencher(&mut info.manufacturerID, crate::NOME);
        preencher(
            &mut info.libraryDescription,
            "RemoteID (Certisign) em nuvem",
        );
        CKR_OK
    })
}

// Slot e token

pub(super) unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        modulo!(guarda).acompanhar();
        // O slot sempre tem token, mesmo sem conta: ver `C_GetTokenInfo`.
        entregar_lista(&[ID_SLOT], pSlotList, pulCount)
    })
}

pub(super) unsafe extern "C" fn C_GetSlotInfo(
    slotID: CK_SLOT_ID,
    pInfo: *mut CK_SLOT_INFO,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        modulo!(guarda).acompanhar();
        if let Err(rv) = conferir_slot(slotID) {
            return rv;
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
        // Sem CKF_HW_SLOT: o HSM é hardware, mas do outro lado da rede. Com
        // CKF_REMOVABLE_DEVICE: é o que faz o NSS voltar a conferir o slot e,
        // achando a sessão dele inválida, reler o token quando a conta muda
        // (ver `Modulo::acompanhar`).
        info.flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE;
        info.hardwareVersion = VERSAO;
        info.firmwareVersion = VERSAO;
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_GetTokenInfo(
    slotID: CK_SLOT_ID,
    pInfo: *mut CK_TOKEN_INFO,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        modulo.acompanhar();
        if let Err(rv) = conferir_slot(slotID) {
            return rv;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let info = &mut *pInfo;
        preencher(&mut info.label, "RemoteID Certisign");
        preencher(&mut info.manufacturerID, "Certisign");
        preencher(&mut info.model, "RemoteID");
        // O campo tem 16 caracteres e a série tem 40: fica o fim, a parte que
        // varia entre certificados do mesmo titular.
        let serie = modulo
            .token
            .as_ref()
            .map_or("", |t| t.certificado.serial_number.as_str());
        preencher(
            &mut info.serialNumber,
            &serie[serie.len().saturating_sub(16)..],
        );
        // Sem conta, o token existe sem estar inicializado, como o slot livre
        // do SoftHSM, e não tem objeto nenhum. Um slot sem token faria o
        // `C_GetSlotList(CK_TRUE)` devolver a lista vazia, e pelo RPC do
        // p11-kit a segunda passada com zero itens volta
        // `CKR_BUFFER_TOO_SMALL`: quem repete enquanto o buffer é pequeno (o
        // crate `cryptoki`, que a sonda do Âncora usa) fica em laço para
        // sempre. Medido no p11-kit 0.26 do runtime GNOME 51.
        //
        // Sem CKF_LOGIN_REQUIRED e sem CKF_USER_PIN_INITIALIZED, de propósito:
        // o token não tem PIN próprio, o do certificado é pedido no C_Sign.
        // Anunciar login fazia o NSS e o poppler pedirem uma senha ao
        // hospedeiro e recusá-la em laço antes de assinar (o Papers pedia o
        // PIN seis vezes no RemoteID-linux).
        info.flags = CKF_WRITE_PROTECTED;
        if modulo.token.is_some() {
            info.flags |= CKF_TOKEN_INITIALIZED;
        }
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
        info.ulSessionCount = modulo.sessoes.len() as CK_ULONG;
        info.ulMaxRwSessionCount = 0;
        info.ulRwSessionCount = 0;
        // Não pode ser 0: o NSS confere o tamanho da senha contra o máximo
        // antes do C_Login, e com 0 recusa toda senha sem tentar.
        info.ulMinPinLen = 1;
        info.ulMaxPinLen = 255;
        info.ulTotalPublicMemory = INDISPONIVEL;
        info.ulFreePublicMemory = INDISPONIVEL;
        info.ulTotalPrivateMemory = INDISPONIVEL;
        info.ulFreePrivateMemory = INDISPONIVEL;
        info.hardwareVersion = VERSAO;
        info.firmwareVersion = VERSAO;
        preencher(&mut info.utcTime, "");
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: *mut CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        modulo!(guarda);
        if let Err(rv) = conferir_slot(slotID) {
            return rv;
        }
        entregar_lista(&MECANISMOS, pMechanismList, pulCount)
    })
}

pub(super) unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        modulo!(guarda);
        if let Err(rv) = conferir_slot(slotID) {
            return rv;
        }
        if !MECANISMOS.contains(&type_) {
            return CKR_MECHANISM_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // O CKM_RSA_PKCS anuncia cifra além de assinatura, ao contrário do
        // módulo oficial. Desde o JDK 11.0.6 (JDK-8176837) o SunPKCS11 só
        // registra o `Cipher.RSA/ECB/PKCS1Padding` de um token que anuncia
        // CKF_ENCRYPT, e esse Cipher é a única porta da JCA para RSA cru: sem
        // ele o signer4j do PJeOffice cai num provedor de software e não
        // autentica. Com a chave privada ele vira C_SignInit e C_Sign; o
        // C_Encrypt de verdade só cifra com a pública.
        let flags = if type_ == CKM_RSA_PKCS {
            CKF_SIGN | CKF_ENCRYPT
        } else {
            CKF_SIGN
        };
        *pInfo = CK_MECHANISM_INFO {
            ulMinKeySize: BITS_CHAVE,
            ulMaxKeySize: BITS_CHAVE,
            flags,
        };
        CKR_OK
    })
}

// Sessões

pub(super) unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: *mut c_void,
    _Notify: CK_NOTIFY,
    phSession: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        modulo.acompanhar();
        if let Err(rv) = conferir_slot(slotID) {
            return rv;
        }
        if phSession.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        // O token é só de leitura: uma sessão R/W seria promessa vazia.
        if flags & CKF_RW_SESSION != 0 {
            return CKR_TOKEN_WRITE_PROTECTED;
        }
        *phSession = modulo.nova_sessao(flags);
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        match modulo!(guarda).sessoes.remove(&hSession) {
            Some(_) => CKR_OK,
            None => CKR_SESSION_HANDLE_INVALID,
        }
    })
}

pub(super) unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        if slotID != ID_SLOT {
            return CKR_SLOT_ID_INVALID;
        }
        modulo.sessoes.clear();
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: *mut CK_SESSION_INFO,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        *pInfo = CK_SESSION_INFO {
            slotID: ID_SLOT,
            // Tem de refletir o login: o NSS confere aqui, depois do C_Login,
            // e com a sessão ainda pública pede a senha de novo, em laço.
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

// Objetos

unsafe fn ler_gabarito(
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, CK_RV> {
    if ulCount == 0 {
        return Ok(Vec::new());
    }
    if pTemplate.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    std::slice::from_raw_parts(pTemplate, ulCount as usize)
        .iter()
        .map(|a| {
            if a.ulValueLen == INDISPONIVEL {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            Ok((
                a.type_,
                bloco_do_host(a.pValue as *mut CK_BYTE, a.ulValueLen)?.to_vec(),
            ))
        })
        .collect()
}

pub(super) unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let gabarito = match ler_gabarito(pTemplate, ulCount) {
            Ok(g) => g,
            Err(rv) => return rv,
        };
        let achados = modulo
            .token
            .as_ref()
            .map(|t| t.buscar(&gabarito))
            .unwrap_or_default();
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if sessao.busca.is_some() {
            return CKR_OPERATION_ACTIVE;
        }
        sessao.busca = Some(achados);
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let Some(sessao) = modulo!(guarda).sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(fila) = sessao.busca.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if pulObjectCount.is_null() || (phObject.is_null() && ulMaxObjectCount != 0) {
            return CKR_ARGUMENTS_BAD;
        }
        let n = fila.len().min(ulMaxObjectCount as usize);
        for (i, h) in fila.drain(..n).enumerate() {
            *phObject.add(i) = h;
        }
        *pulObjectCount = n as CK_ULONG;
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let Some(sessao) = modulo!(guarda).sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        match sessao.busca.take() {
            Some(_) => CKR_OK,
            None => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
}

/// Duas passadas, como manda a especificação, e o erro é por atributo: os que
/// existem são copiados mesmo quando outro falta, e o que faltou fica com
/// `CK_UNAVAILABLE_INFORMATION`. Abortar na primeira falta deixaria o
/// hospedeiro sem nada por perguntar um atributo a mais.
pub(super) unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let Some(objeto) = modulo.token.as_ref().and_then(|t| t.objeto(hObject)) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        if pTemplate.is_null() && ulCount != 0 {
            return CKR_ARGUMENTS_BAD;
        }
        copiar_atributos(objeto, pTemplate, ulCount)
    })
}

unsafe fn copiar_atributos(
    objeto: &Objeto,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    let mut rv = CKR_OK;
    for i in 0..ulCount as usize {
        let attr = &mut *pTemplate.add(i);
        // Antes de procurar: `CKA_VALUE` existe no certificado, mas na chave
        // privada é sensível.
        if objeto.e_sensivel(attr.type_) {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_ATTRIBUTE_SENSITIVE;
            continue;
        }
        let Some(valor) = objeto.atributo(attr.type_) else {
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

// Login

/// O login não autentica nada: o PIN e o OTP do certificado são pedidos no
/// `C_Sign`. Existe para o hospedeiro que insiste em chamá-lo.
pub(super) unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    _pPin: *mut CK_UTF8CHAR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if userType != CKU_USER {
            return CKR_USER_TYPE_INVALID;
        }
        if modulo.logado {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        modulo.logado = true;
        CKR_OK
    })
}

pub(super) unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
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

// Assinatura e cifra

/// O mecanismo pedido, se for um de `permitidos`. Nenhum deles tem parâmetro;
/// um parâmetro é sinal de que o hospedeiro queria PSS ou OAEP.
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

/// O começo comum de `C_SignInit` e `C_EncryptInit`: a chave tem de existir e
/// ser da `classe` que a operação usa.
unsafe fn iniciar(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
    permitidos: &[CK_MECHANISM_TYPE],
    classe: CK_OBJECT_CLASS,
    operacao: fn(&mut super::Sessao) -> &mut Option<Operacao>,
) -> CK_RV {
    let mut guarda = trava(&MODULO);
    let modulo = modulo!(guarda);
    if !modulo.sessoes.contains_key(&hSession) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let mecanismo = match ler_mecanismo(pMechanism, permitidos) {
        Ok(m) => m,
        Err(rv) => return rv,
    };
    match modulo
        .token
        .as_ref()
        .and_then(|t| t.objeto(hKey))
        .map(Objeto::classe)
    {
        Some(Some(c)) if c == classe => {}
        // É uma chave, mas não serve para esta operação.
        Some(Some(CKO_PRIVATE_KEY | CKO_PUBLIC_KEY)) => return CKR_KEY_FUNCTION_NOT_PERMITTED,
        _ => return CKR_KEY_HANDLE_INVALID,
    }
    let ativa = operacao(modulo.sessoes.get_mut(&hSession).expect("conferida acima"));
    if ativa.is_some() {
        return CKR_OPERATION_ACTIVE;
    }
    *ativa = Some(Operacao {
        mecanismo,
        acumulado: Vec::new(),
    });
    CKR_OK
}

pub(super) unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    entrada!({
        iniciar(
            hSession,
            pMechanism,
            hKey,
            &MECANISMOS,
            CKO_PRIVATE_KEY,
            |s| &mut s.assinatura,
        )
    })
}

/// Um bloco do hospedeiro. Comprimento zero é legítimo, e aí o ponteiro pode
/// ser nulo.
unsafe fn bloco_do_host<'a>(p: *mut CK_BYTE, n: CK_ULONG) -> Result<&'a [u8], CK_RV> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(std::slice::from_raw_parts(p, n as usize))
}

/// A parte das duas passadas que `C_Sign`, `C_SignFinal` e `C_Encrypt` têm
/// igual: com o buffer nulo só o tamanho, com o buffer pequeno o erro, e nos
/// dois casos a operação continua ativa, para o hospedeiro voltar com espaço.
/// `Err` é a resposta pronta.
unsafe fn conferir_saida(
    bytes: usize,
    pSaida: *mut CK_BYTE,
    pulSaidaLen: *mut CK_ULONG,
) -> Result<(), CK_RV> {
    if pulSaidaLen.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let cabe = *pulSaidaLen as usize >= bytes;
    *pulSaidaLen = bytes as CK_ULONG;
    if pSaida.is_null() {
        return Err(CKR_OK);
    }
    if !cabe {
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    Ok(())
}

unsafe fn entregar(
    bloco: &[u8],
    bytes: usize,
    pSaida: *mut CK_BYTE,
    pulSaidaLen: *mut CK_ULONG,
) -> CK_RV {
    // Um RSA-2048 sempre dá 256 bytes; outra coisa é defeito, e o hospedeiro
    // a recusaria adiante.
    if bloco.len() != bytes {
        return CKR_FUNCTION_FAILED;
    }
    std::ptr::copy_nonoverlapping(bloco.as_ptr(), pSaida, bytes);
    *pulSaidaLen = bytes as CK_ULONG;
    CKR_OK
}

/// O fim comum de `C_Sign` (com `dados`) e `C_SignFinal` (com o acumulado).
///
/// A operação é tirada da sessão sob a trava, e a assinatura acontece sem
/// ela: pode levar o tempo de a pessoa digitar o PIN e o OTP, e nesse tempo o
/// mesmo aplicativo continua listando tokens e abrindo sessões.
unsafe fn assinar_e_entregar(
    hSession: CK_SESSION_HANDLE,
    dados: Option<&[u8]>,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    let (operacao, certificado, bytes) = {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let bytes = modulo.token.as_ref().map(Token::bytes_bloco);
        let certificado = modulo.token.as_ref().map(|t| t.certificado.clone());
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if sessao.assinatura.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        let (Some(bytes), Some(certificado)) = (bytes, certificado) else {
            sessao.assinatura = None;
            return CKR_TOKEN_NOT_PRESENT;
        };
        if let Err(rv) = conferir_saida(bytes, pSignature, pulSignatureLen) {
            return rv;
        }
        (
            sessao.assinatura.take().expect("conferida acima"),
            certificado,
            bytes,
        )
    };
    let dados = dados.unwrap_or(&operacao.acumulado);
    match assinar(operacao.mecanismo, &certificado, dados) {
        Ok(assinatura) => entregar(&assinatura, bytes, pSignature, pulSignatureLen),
        Err(rv) => rv,
    }
}

/// Assinatura de uma parte só, a do poppler ao assinar PDF.
pub(super) unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        match bloco_do_host(pData, ulDataLen) {
            Ok(dados) => assinar_e_entregar(hSession, Some(dados), pSignature, pulSignatureLen),
            Err(rv) => rv,
        }
    })
}

pub(super) unsafe extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: *mut CK_BYTE,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let Some(sessao) = modulo!(guarda).sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(operacao) = sessao.assinatura.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        match bloco_do_host(pPart, ulPartLen) {
            Ok(pedaco) => {
                operacao.acumulado.extend_from_slice(pedaco);
                CKR_OK
            }
            Err(rv) => rv,
        }
    })
}

pub(super) unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!({ assinar_e_entregar(hSession, None, pSignature, pulSignatureLen) })
}

/// O que cada mecanismo faz com os bytes antes de irem ao HSM:
///
/// - `CKM_RSA_PKCS`: os bytes já são o bloco (em geral um DigestInfo), e o
///   HSM só aplica o padding. É o modo cru do servidor, e é por ele que o
///   DigestInfo(MD5) do PJeOffice chega lá.
/// - `CKM_SHA256_RSA_PKCS`: os bytes são o conteúdo; o hash é feito aqui e o
///   HSM monta o DigestInfo(SHA-256).
fn preparar_bloco(
    mecanismo: CK_MECHANISM_TYPE,
    dados: &[u8],
) -> Result<(Algoritmo, Vec<u8>), CK_RV> {
    let (algoritmo, bloco) = match mecanismo {
        CKM_RSA_PKCS => (Algoritmo::Cru, dados.to_vec()),
        CKM_SHA256_RSA_PKCS => (Algoritmo::Sha256, sha256(dados).to_vec()),
        _ => return Err(CKR_MECHANISM_INVALID),
    };
    if !algoritmo.aceita(&bloco) {
        return Err(CKR_DATA_LEN_RANGE);
    }
    Ok((algoritmo, bloco))
}

fn assinar(
    mecanismo: CK_MECHANISM_TYPE,
    certificado: &Certificado,
    dados: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let (algoritmo, bloco) = preparar_bloco(mecanismo, dados)?;
    let dialogo = Dialogo::do_ambiente().ok_or(CKR_FUNCTION_FAILED)?;
    let mut guarda = trava(&MOTOR);
    if guarda.is_none() {
        let caminhos = Caminhos::do_ambiente();
        let diagnostico = Diagnostico::abrir(&caminhos.diagnostico());
        let motor = Motor::abrir(
            caminhos,
            caminhos::servidor(),
            Box::new(Http::novo(TEMPO_LIMITE)),
        )
        .map_err(|e| rv_do_erro(&e))?;
        *guarda = Some(motor.com_diagnostico(diagnostico));
    }
    let motor = guarda.as_mut().expect("aberto acima");
    motor.recarregar().map_err(|e| rv_do_erro(&e))?;
    motor
        .assinar_com(certificado, algoritmo, &bloco, &dialogo)
        .map_err(|e| rv_do_erro(&e))
}

/// O que o hospedeiro entende de cada falha. Ele não mostra a mensagem do
/// servidor; o diagnóstico guarda o resto.
fn rv_do_erro(erro: &Erro) -> CK_RV {
    match erro {
        Erro::Cancelado => CKR_FUNCTION_CANCELED,
        Erro::BlocoInvalido => CKR_DATA_LEN_RANGE,
        Erro::Protocolo(ErroProtocolo::Servidor {
            regra: Some(regra), ..
        }) if regra.origem == Origem::Usuario => CKR_PIN_INCORRECT,
        Erro::Rede(_) | Erro::Disco(_) | Erro::NaoPreparado(_) => CKR_DEVICE_ERROR,
        Erro::Protocolo(_) => CKR_FUNCTION_FAILED,
    }
}

/// Cifra com a chave pública do certificado. A privada é recusada: cifrar
/// com ela não é operação do PKCS#11 (o SunPKCS11 a transforma em
/// `C_SignInit` e `C_Sign`, e nunca chega aqui).
pub(super) unsafe extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    entrada!({
        iniciar(
            hSession,
            pMechanism,
            hKey,
            &[CKM_RSA_PKCS],
            CKO_PUBLIC_KEY,
            |s| &mut s.cifra,
        )
    })
}

/// O `CKM_RSA_PKCS` é de uma parte só: `C_EncryptUpdate` e `C_EncryptFinal`
/// ficam sem suporte.
pub(super) unsafe extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pEncryptedData: *mut CK_BYTE,
    pulEncryptedDataLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!({
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let Some(token) = modulo.token.as_ref() else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        let bytes = token.bytes_bloco();
        let publica = token.publica.clone();
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if sessao.cifra.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if let Err(rv) = conferir_saida(bytes, pEncryptedData, pulEncryptedDataLen) {
            return rv;
        }
        sessao.cifra = None;
        let dados = match bloco_do_host(pData, ulDataLen) {
            Ok(d) if Algoritmo::Cru.aceita(d) => d,
            Ok(_) => return CKR_DATA_LEN_RANGE,
            Err(rv) => return rv,
        };
        match publica.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, dados) {
            Ok(cifrado) => entregar(&cifrado, bytes, pEncryptedData, pulEncryptedDataLen),
            Err(_) => CKR_FUNCTION_FAILED,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campo_de_texto_e_completado_com_espaco_e_truncado() {
        let mut campo = [0u8; 8];
        preencher(&mut campo, "abc");
        assert_eq!(&campo, b"abc     ");
        let mut curto = [0u8; 4];
        preencher(&mut curto, "abcdefgh");
        assert_eq!(&curto, b"abcd");
    }

    #[test]
    fn cada_mecanismo_prepara_o_que_o_servidor_espera() {
        let digest_info = [0x30; 51];
        assert_eq!(
            preparar_bloco(CKM_RSA_PKCS, &digest_info),
            Ok((Algoritmo::Cru, digest_info.to_vec()))
        );
        assert_eq!(
            preparar_bloco(CKM_SHA256_RSA_PKCS, b"documento"),
            Ok((Algoritmo::Sha256, sha256(b"documento").to_vec()))
        );
        // O teto do PKCS#1 v1.5 para RSA-2048, e o vazio, não vão ao servidor.
        assert_eq!(
            preparar_bloco(CKM_RSA_PKCS, &[0; 246]),
            Err(CKR_DATA_LEN_RANGE)
        );
        assert_eq!(preparar_bloco(CKM_RSA_PKCS, &[]), Err(CKR_DATA_LEN_RANGE));
        // Conteúdo de qualquer tamanho vira 32 bytes.
        assert!(preparar_bloco(CKM_SHA256_RSA_PKCS, &[]).is_ok());
    }
}
