//! Stubs das funções Cryptoki que este módulo ainda não implementa.
//!
//! ARQUIVO GERADO por `tools/gerar-stubs-pkcs11.py`. Não editar à mão.
//!
//! Nenhum ponteiro da `CK_FUNCTION_LIST` pode ser NULL — o p11-kit e o NSS
//! chamam sem checar —, então toda função existe, e a que não implementamos
//! devolve `CKR_FUNCTION_NOT_SUPPORTED`, que é o que a especificação manda.

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

use cryptoki_sys::*;

pub unsafe extern "C" fn C_InitToken(
    _: CK_SLOT_ID,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
    _: *mut CK_UTF8CHAR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_InitPIN(
    _: CK_SESSION_HANDLE,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SetPIN(
    _: CK_SESSION_HANDLE,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
    _: *mut CK_UTF8CHAR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GetOperationState(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SetOperationState(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_CreateObject(
    _: CK_SESSION_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_CopyObject(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DestroyObject(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GetObjectSize(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SetAttributeValue(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_EncryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_EncryptFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_Decrypt(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestInit(_: CK_SESSION_HANDLE, _: *mut CK_MECHANISM) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_Digest(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestKey(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SignRecoverInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SignRecover(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_Verify(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyFinal(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyRecoverInit(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyRecover(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestEncryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptDigestUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SignEncryptUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptVerifyUpdate(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GenerateKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GenerateKeyPair(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_WrapKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_BYTE,
    _: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_UnwrapKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DeriveKey(
    _: CK_SESSION_HANDLE,
    _: *mut CK_MECHANISM,
    _: CK_OBJECT_HANDLE,
    _: *mut CK_ATTRIBUTE,
    _: CK_ULONG,
    _: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SeedRandom(_: CK_SESSION_HANDLE, _: *mut CK_BYTE, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GenerateRandom(
    _: CK_SESSION_HANDLE,
    _: *mut CK_BYTE,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GetFunctionStatus(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_CancelFunction(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_WaitForSlotEvent(
    _: CK_FLAGS,
    _: *mut CK_SLOT_ID,
    _: *mut ::std::os::raw::c_void,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
