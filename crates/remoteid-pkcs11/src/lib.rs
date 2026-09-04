//! Módulo PKCS#11 (Cryptoki) do certificado em nuvem RemoteID.
//!
//! # Por que este crate existe
//!
//! O GNOME Papers não assina PDF: quem assina é o `poppler`, que monta o CMS
//! sozinho e tira os certificados do NSS. O nosso `pkcs7.rs` não é chamado em
//! nenhum ponto desse caminho. Para o certificado em nuvem aparecer para o
//! Papers, ele tem de entrar pelo NSS — e como a chave privada mora no HSM da
//! Certisign, o único caminho é um módulo PKCS#11 cujo `C_Sign` chame o motor.
//! Ver [[remoteid-pkcs7-e-o-caminho-do-papers]].
//!
//! ```text
//! GNOME Papers → poppler → NSS → p11-kit-proxy → ESTE MÓDULO → motor → HSM
//! ```
//!
//! # O que já está implementado
//!
//! As fatias offline: enumerar o slot/token e **mostrar o certificado**. Isso
//! não vai à rede, não pede PIN e não gasta OTP, e é verificável com
//! `p11-kit list-modules` e `certutil`. A assinatura (`C_Sign`) ainda não: as
//! funções que faltam devolvem `CKR_FUNCTION_NOT_SUPPORTED` (ver `stubs.rs`).
//!
//! # Regras que valem para todo este crate
//!
//! - **Nada de `panic!` atravessando a fronteira FFI.** Este `.so` é carregado
//!   dentro do processo alheio (Papers, Firefox); desenrolar a pilha por cima
//!   de um frame C é comportamento indefinido, e derrubar o hospedeiro é pior
//!   que devolver erro. Toda função exportada passa pela macro [`entrada`].
//! - **Nada de escrever em stdout/stderr.** O hospedeiro é dono desses
//!   descritores.

// Os nomes vêm da especificação Cryptoki, que é C: `C_GetSlotList`, não
// `c_get_slot_list`. Renomear quebraria a correspondência com o header.
#![allow(non_snake_case)]

mod cliente;
mod funcoes;
pub mod objetos;
pub mod stubs;
pub mod token;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use cryptoki_sys::*;

use token::Token;

/// Estado do módulo. `None` = ainda não passou por `C_Initialize`.
///
/// Um `Mutex` só, e grosso, de propósito: a especificação permite chamadas
/// concorrentes, o volume aqui é irrisório (um certificado, meia dúzia de
/// sessões), e serializar tudo elimina de saída a classe de bug mais cara de
/// depurar dentro do processo de outra pessoa.
static MODULO: Mutex<Option<Modulo>> = Mutex::new(None);

pub(crate) struct Modulo {
    /// `None` quando a instalação ainda não foi preparada: o slot existe, mas
    /// sem token dentro.
    pub token: Option<Token>,
    pub sessoes: HashMap<CK_SESSION_HANDLE, Sessao>,
    proximo_handle: CK_SESSION_HANDLE,
    /// Login é POR APLICAÇÃO, não por sessão: a especificação manda que, ao
    /// logar em uma sessão, todas as sessões da mesma aplicação passem a estar
    /// logadas. Como toda sessão passa por este `MODULO` global, um booleano
    /// aqui basta.
    pub logado: bool,
}

impl Modulo {
    fn nova_sessao(&mut self, flags: CK_FLAGS) -> CK_SESSION_HANDLE {
        let h = self.proximo_handle;
        self.proximo_handle += 1;
        self.sessoes.insert(
            h,
            Sessao {
                flags,
                busca: None,
                assinatura: None,
            },
        );
        h
    }
}

pub(crate) struct Sessao {
    pub flags: CK_FLAGS,
    /// Os handles que sobraram da busca corrente. `None` = nenhuma busca ativa.
    ///
    /// O Cryptoki entrega o resultado da busca em pedaços, então o que a
    /// sessão guarda é a fila do que ainda não foi devolvido.
    pub busca: Option<Vec<CK_OBJECT_HANDLE>>,
    /// Estado da operação de assinatura desta sessão. Uma sessão só pode ter uma.
    pub assinatura: Option<EstadoAssinatura>,
}

/// O que `C_SignInit` fixa: com qual chave e por qual mecanismo. O digest de
/// entrada em si só chega no `C_Sign`.
pub(crate) struct EstadoAssinatura {
    #[allow(dead_code)] // usado quando um segundo mecanismo entrar
    pub mecanismo: CK_MECHANISM_TYPE,
    #[allow(dead_code)] // o `C_Sign` já lê a chave do token pela chave_teste;
    // o handle fica registrado para depuração e para o dia
    // em que houver mais de uma chave.
    pub chave: CK_OBJECT_HANDLE,
}

/// Tranca o estado global, recuperando de envenenamento.
///
/// Um `panic` em uma chamada não pode inutilizar o módulo para o resto da vida
/// do processo hospedeiro: um Firefox aberto há três dias não vai ser reiniciado
/// porque uma busca deu errado.
pub(crate) fn trava() -> MutexGuard<'static, Option<Modulo>> {
    MODULO.lock().unwrap_or_else(|e| e.into_inner())
}

/// Envolve o corpo de uma função exportada.
///
/// Converte qualquer `panic` em `CKR_GENERAL_ERROR` em vez de deixá-lo
/// atravessar a fronteira FFI. Ver a nota no topo do módulo.
macro_rules! entrada {
    ($corpo:block) => {
        match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| $corpo)) {
            Ok(rv) => rv,
            Err(_) => cryptoki_sys::CKR_GENERAL_ERROR,
        }
    };
}
pub(crate) use entrada;

/// A tabela de funções, na versão 2.40 do Cryptoki.
///
/// 2.40 e não 3.x de propósito: é a que o NSS pede por `C_GetFunctionList`, e é
/// o denominador comum que p11-kit, NSS e GnuTLS carregam sem negociação.
///
/// O literal usa campos nomeados, então o compilador — não a ordem em que estas
/// linhas foram digitadas — garante que cada ponteiro cai no lugar certo, e um
/// campo esquecido é erro de compilação, não um NULL que o hospedeiro chama.
static LISTA: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(funcoes::C_Initialize),
    C_Finalize: Some(funcoes::C_Finalize),
    C_GetInfo: Some(funcoes::C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(funcoes::C_GetSlotList),
    C_GetSlotInfo: Some(funcoes::C_GetSlotInfo),
    C_GetTokenInfo: Some(funcoes::C_GetTokenInfo),
    C_GetMechanismList: Some(funcoes::C_GetMechanismList),
    C_GetMechanismInfo: Some(funcoes::C_GetMechanismInfo),
    C_OpenSession: Some(funcoes::C_OpenSession),
    C_CloseSession: Some(funcoes::C_CloseSession),
    C_CloseAllSessions: Some(funcoes::C_CloseAllSessions),
    C_GetSessionInfo: Some(funcoes::C_GetSessionInfo),
    C_FindObjectsInit: Some(funcoes::C_FindObjectsInit),
    C_FindObjects: Some(funcoes::C_FindObjects),
    C_FindObjectsFinal: Some(funcoes::C_FindObjectsFinal),
    C_GetAttributeValue: Some(funcoes::C_GetAttributeValue),

    // --- ainda não implementadas (ver `stubs.rs`) ---
    C_InitToken: Some(stubs::C_InitToken),
    C_InitPIN: Some(stubs::C_InitPIN),
    C_SetPIN: Some(stubs::C_SetPIN),
    C_GetOperationState: Some(stubs::C_GetOperationState),
    C_SetOperationState: Some(stubs::C_SetOperationState),
    C_Login: Some(funcoes::C_Login),
    C_Logout: Some(funcoes::C_Logout),
    C_CreateObject: Some(stubs::C_CreateObject),
    C_CopyObject: Some(stubs::C_CopyObject),
    C_DestroyObject: Some(stubs::C_DestroyObject),
    C_GetObjectSize: Some(stubs::C_GetObjectSize),
    C_SetAttributeValue: Some(stubs::C_SetAttributeValue),
    C_EncryptInit: Some(stubs::C_EncryptInit),
    C_Encrypt: Some(stubs::C_Encrypt),
    C_EncryptUpdate: Some(stubs::C_EncryptUpdate),
    C_EncryptFinal: Some(stubs::C_EncryptFinal),
    C_DecryptInit: Some(stubs::C_DecryptInit),
    C_Decrypt: Some(stubs::C_Decrypt),
    C_DecryptUpdate: Some(stubs::C_DecryptUpdate),
    C_DecryptFinal: Some(stubs::C_DecryptFinal),
    C_DigestInit: Some(stubs::C_DigestInit),
    C_Digest: Some(stubs::C_Digest),
    C_DigestUpdate: Some(stubs::C_DigestUpdate),
    C_DigestKey: Some(stubs::C_DigestKey),
    C_DigestFinal: Some(stubs::C_DigestFinal),
    C_SignInit: Some(funcoes::C_SignInit),
    C_Sign: Some(funcoes::C_Sign),
    C_SignUpdate: Some(stubs::C_SignUpdate),
    C_SignFinal: Some(stubs::C_SignFinal),
    C_SignRecoverInit: Some(stubs::C_SignRecoverInit),
    C_SignRecover: Some(stubs::C_SignRecover),
    C_VerifyInit: Some(stubs::C_VerifyInit),
    C_Verify: Some(stubs::C_Verify),
    C_VerifyUpdate: Some(stubs::C_VerifyUpdate),
    C_VerifyFinal: Some(stubs::C_VerifyFinal),
    C_VerifyRecoverInit: Some(stubs::C_VerifyRecoverInit),
    C_VerifyRecover: Some(stubs::C_VerifyRecover),
    C_DigestEncryptUpdate: Some(stubs::C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(stubs::C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(stubs::C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(stubs::C_DecryptVerifyUpdate),
    C_GenerateKey: Some(stubs::C_GenerateKey),
    C_GenerateKeyPair: Some(stubs::C_GenerateKeyPair),
    C_WrapKey: Some(stubs::C_WrapKey),
    C_UnwrapKey: Some(stubs::C_UnwrapKey),
    C_DeriveKey: Some(stubs::C_DeriveKey),
    C_SeedRandom: Some(stubs::C_SeedRandom),
    C_GenerateRandom: Some(stubs::C_GenerateRandom),
    C_GetFunctionStatus: Some(stubs::C_GetFunctionStatus),
    C_CancelFunction: Some(stubs::C_CancelFunction),
    C_WaitForSlotEvent: Some(stubs::C_WaitForSlotEvent),
};

/// O ponto de entrada do módulo: é o único símbolo que o hospedeiro procura por
/// nome, e o resto do ABI sai da tabela que ele devolve.
///
/// Funciona ANTES de `C_Initialize` — o p11-kit chama exatamente nessa ordem.
///
/// # Safety
///
/// `ppFunctionList` tem de ser um ponteiro válido para escrita, como manda a
/// especificação.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    entrada!({
        if ppFunctionList.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // A tabela é `static` e o hospedeiro só a lê; a especificação é escrita
        // em C, onde o ponteiro é não-const por convenção do header.
        *ppFunctionList = &LISTA as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
        CKR_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tabela_nao_tem_ponteiro_nulo() {
        // O p11-kit e o NSS chamam sem checar por NULL; um campo esquecido aqui
        // vira segfault dentro do Firefox, não erro de retorno.
        let bytes: &[usize] = unsafe {
            std::slice::from_raw_parts(
                (&LISTA as *const CK_FUNCTION_LIST as *const usize).add(1),
                (std::mem::size_of::<CK_FUNCTION_LIST>() - std::mem::size_of::<usize>())
                    / std::mem::size_of::<usize>(),
            )
        };
        assert_eq!(bytes.len(), 68, "a lista 2.40 tem 68 funções");
        assert!(
            bytes.iter().all(|p| *p != 0),
            "há ponteiro NULL na CK_FUNCTION_LIST"
        );
    }

    #[test]
    fn get_function_list_devolve_a_tabela_e_recusa_ponteiro_nulo() {
        let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
        assert_eq!(unsafe { C_GetFunctionList(&mut p) }, CKR_OK);
        assert!(!p.is_null());
        assert_eq!(unsafe { (*p).version.major }, 2);
        assert_eq!(unsafe { (*p).version.minor }, 40);
        assert_eq!(
            unsafe { C_GetFunctionList(std::ptr::null_mut()) },
            CKR_ARGUMENTS_BAD
        );
    }
}
