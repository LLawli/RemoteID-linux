//! O módulo PKCS#11 (Cryptoki 2.40) que o p11-kit carrega: o certificado da
//! carteira como token, e o `C_Sign` assinando pelo motor, no HSM da
//! Certisign.
//!
//! Regras que valem para todo este módulo, porque ele roda dentro do processo
//! de outro (o `p11-kit-remote` de cada conexão ao `p11-kit server` do Âncora):
//!
//! - **Nenhum `panic` atravessa a fronteira C.** Toda função exportada passa
//!   por [`entrada`], que o converte em `CKR_GENERAL_ERROR` e grava mensagem
//!   e local no registro.
//! - **Nada no stdout nem no stderr.** O stdout é o canal do protocolo.
//! - **Nenhuma trava segura uma pergunta à pessoa.** O `C_Sign` solta a trava
//!   do módulo antes de ir ao motor, para o diálogo de PIN e OTP não congelar
//!   as outras chamadas do mesmo aplicativo.

// Os nomes são os da especificação, que é C: `C_GetSlotList`, `pulCount`.
#![allow(non_snake_case)]

mod funcoes;
mod objetos;
mod registro;
mod stubs;
mod token;

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use cryptoki_sys::*;

use crate::estado::Estado;
use crate::motor::Motor;
use token::Token;

/// O estado do módulo. `None` antes do `C_Initialize`.
///
/// Uma trava só, e grossa: o volume é irrisório (um certificado, meia dúzia de
/// sessões), e serializar tudo elimina a classe de bug mais cara de depurar
/// dentro do processo de outro. A exceção é a assinatura, que vai ao
/// [`MOTOR`] sem ela.
static MODULO: Mutex<Option<Modulo>> = Mutex::new(None);

/// O motor, aberto na primeira assinatura e não antes: a sonda do Âncora
/// carrega o módulo a cada 10 s e não pode gerar chave nem criar arquivo de
/// diagnóstico. Duas assinaturas do mesmo aplicativo esperam uma pela outra
/// aqui, e a segunda aproveita a sessão que a primeira abriu.
static MOTOR: Mutex<Option<Motor>> = Mutex::new(None);

struct Modulo {
    token: Option<Token>,
    /// O `estado.json` de onde o token saiu, e a identidade dele quando foi
    /// lido.
    estado: PathBuf,
    identidade: Option<Identidade>,
    sessoes: HashMap<CK_SESSION_HANDLE, Sessao>,
    proximo_handle: CK_SESSION_HANDLE,
    /// O login vale para a aplicação inteira, não para uma sessão.
    logado: bool,
}

#[derive(Default)]
struct Sessao {
    flags: CK_FLAGS,
    /// O que sobrou da busca corrente: o Cryptoki a entrega em pedaços.
    busca: Option<Vec<CK_OBJECT_HANDLE>>,
    assinatura: Option<Operacao>,
    cifra: Option<Operacao>,
}

/// Uma operação de assinatura ou cifra, do `Init` até o fim.
///
/// Quem assina em fluxo (`C_SignUpdate`, depois `C_SignFinal`) junta os dados
/// aqui. Não é exotismo: o BouncyCastle nunca chama `C_Sign`, e é assim que o
/// PJeOffice assina.
struct Operacao {
    mecanismo: CK_MECHANISM_TYPE,
    acumulado: Vec<u8>,
}

/// O que muda a cada gravação do estado: a troca atômica cria um inode novo.
type Identidade = (u64, SystemTime);

fn identidade(caminho: &Path) -> Option<Identidade> {
    let metadados = std::fs::metadata(caminho).ok()?;
    Some((metadados.ino(), metadados.modified().ok()?))
}

impl Modulo {
    fn abrir(estado: PathBuf) -> Modulo {
        let mut modulo = Modulo {
            token: None,
            estado,
            identidade: None,
            sessoes: HashMap::new(),
            proximo_handle: 1,
            logado: false,
        };
        modulo.recarregar();
        modulo
    }

    fn recarregar(&mut self) {
        self.identidade = identidade(&self.estado);
        // Um estado ilegível é um token vazio, não um erro: falhar tiraria o
        // módulo de todo aplicativo da máquina por causa de um arquivo nosso.
        let estado = Estado::carregar(&self.estado).unwrap_or_default();
        self.token = Token::do_estado(&estado);
    }

    /// Acompanha o estado em disco numa conexão que fica aberta, como a do
    /// navegador. Uma gravação que não troca o certificado (cada assinatura
    /// grava a sessão em cache) não muda nada. Trocar o certificado, ou entrar
    /// e sair da conta, é tirar um cartão e pôr outro: as sessões acabam, e o
    /// NSS, ao achar a dele inválida, relê o token.
    fn acompanhar(&mut self) {
        if identidade(&self.estado) == self.identidade {
            return;
        }
        let antes = self.token.as_ref().map(|t| t.certificado.clone());
        self.recarregar();
        if self.token.as_ref().map(|t| &t.certificado) != antes.as_ref() {
            self.sessoes.clear();
            self.logado = false;
        }
    }

    fn nova_sessao(&mut self, flags: CK_FLAGS) -> CK_SESSION_HANDLE {
        let h = self.proximo_handle;
        self.proximo_handle += 1;
        self.sessoes.insert(
            h,
            Sessao {
                flags,
                ..Sessao::default()
            },
        );
        h
    }
}

/// Tranca o estado, recuperando de envenenamento: um `panic` numa chamada não
/// pode inutilizar o módulo num navegador aberto há três dias.
fn trava<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Envolve o corpo de uma função exportada: o nome e os argumentos vão para
/// o [`registro`], que também segura o `panic`.
macro_rules! entrada {
    ($nome:literal, $campos:tt, $corpo:block) => {
        $crate::pkcs11::registro::chamada($nome, ::serde_json::json!($campos), || $corpo)
    };
}
use entrada;

/// A tabela de funções, na versão 2.40: a que o NSS pede, e o denominador
/// comum que p11-kit, NSS e GnuTLS carregam sem negociar. Os campos nomeados
/// fazem do compilador, e não da ordem das linhas, a garantia de que cada
/// ponteiro cai no lugar certo.
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
    C_InitToken: Some(stubs::C_InitToken),
    C_InitPIN: Some(stubs::C_InitPIN),
    C_SetPIN: Some(stubs::C_SetPIN),
    C_OpenSession: Some(funcoes::C_OpenSession),
    C_CloseSession: Some(funcoes::C_CloseSession),
    C_CloseAllSessions: Some(funcoes::C_CloseAllSessions),
    C_GetSessionInfo: Some(funcoes::C_GetSessionInfo),
    C_GetOperationState: Some(stubs::C_GetOperationState),
    C_SetOperationState: Some(stubs::C_SetOperationState),
    C_Login: Some(funcoes::C_Login),
    C_Logout: Some(funcoes::C_Logout),
    C_CreateObject: Some(stubs::C_CreateObject),
    C_CopyObject: Some(stubs::C_CopyObject),
    C_DestroyObject: Some(stubs::C_DestroyObject),
    C_GetObjectSize: Some(stubs::C_GetObjectSize),
    C_GetAttributeValue: Some(funcoes::C_GetAttributeValue),
    C_SetAttributeValue: Some(stubs::C_SetAttributeValue),
    C_FindObjectsInit: Some(funcoes::C_FindObjectsInit),
    C_FindObjects: Some(funcoes::C_FindObjects),
    C_FindObjectsFinal: Some(funcoes::C_FindObjectsFinal),
    C_EncryptInit: Some(funcoes::C_EncryptInit),
    C_Encrypt: Some(funcoes::C_Encrypt),
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
    C_SignUpdate: Some(funcoes::C_SignUpdate),
    C_SignFinal: Some(funcoes::C_SignFinal),
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

/// O único símbolo que o hospedeiro procura pelo nome; o resto sai da
/// tabela. Funciona antes do `C_Initialize`, que é a ordem do p11-kit.
///
/// # Safety
///
/// `ppFunctionList` é nulo ou aponta para um ponteiro gravável.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    entrada!("C_GetFunctionList", {}, {
        if ppFunctionList.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // O hospedeiro só lê a tabela; o ponteiro é mutável pela convenção do
        // cabeçalho C.
        unsafe { *ppFunctionList = &raw const LISTA as *mut CK_FUNCTION_LIST };
        CKR_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tabela_nao_tem_ponteiro_nulo() {
        // O p11-kit e o NSS chamam sem conferir: um campo nulo é segfault
        // dentro do navegador, não um erro.
        let ponteiros = (size_of::<CK_FUNCTION_LIST>() - size_of::<usize>()) / size_of::<usize>();
        let tabela = unsafe {
            std::slice::from_raw_parts((&raw const LISTA as *const usize).add(1), ponteiros)
        };
        assert_eq!(tabela.len(), 68, "a lista 2.40 tem 68 funções");
        assert!(tabela.iter().all(|p| *p != 0));
    }
}
