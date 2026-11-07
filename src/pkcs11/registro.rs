//! O registro das chamadas Cryptoki, para quando um navegador ou assinador
//! falha e a pessoa só sabe dizer "não assinou".
//!
//! Cada chamada vira uma linha com a função, os argumentos que não são
//! segredo, o `CKR_*` devolvido e a duração. O PIN do `C_Login` e os dados a
//! assinar nunca entram: dos dados, só o tamanho e a impressão digital.
//!
//! As chamadas de rotina (listar slots, ler atributos) ficam num anel em
//! memória e só vão ao disco junto de uma que importa: uma operação, um erro
//! ou um `panic`. A sonda do Âncora carrega o módulo a cada 10 s e não pode
//! deixar um arquivo por vez; um navegador que falha leva ao disco as últimas
//! [`CONTEXTO`] chamadas antes da falha.

use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Mutex, Once};
use std::time::Instant;

use cryptoki_sys::*;
use serde_json::{Map, Value, json};

use super::trava;
use crate::caminhos::Caminhos;
use crate::cripto::sha256;
use crate::diagnostico::Diagnostico;

/// Quantas chamadas de rotina ficam no anel.
const CONTEXTO: usize = 64;

/// As chamadas que sempre vão ao disco, com o anel antes delas.
const OPERACOES: &[&str] = &[
    "C_Login",
    "C_Logout",
    "C_SignInit",
    "C_Sign",
    "C_SignFinal",
    "C_EncryptInit",
    "C_Encrypt",
];

/// Quantos tipos de atributo de um modelo entram na linha.
const ATRIBUTOS: usize = 32;

struct Registro {
    /// Aberto na primeira chamada que importa, e o mesmo até o fim do
    /// processo: o motor que o `C_Sign` abre grava nele também.
    diagnostico: Option<Diagnostico>,
    contexto: VecDeque<(u64, Value)>,
    /// As de rotina que saíram do anel sem ir ao disco.
    omitidas: u64,
}

static REGISTRO: Mutex<Registro> = Mutex::new(Registro {
    diagnostico: None,
    contexto: VecDeque::new(),
    omitidas: 0,
});

/// A mensagem e o local do último `panic` dentro de uma chamada. Global, e
/// não por thread, para não deixar destrutor de thread pendurado num módulo
/// que o hospedeiro pode descarregar.
static PANICO: Mutex<Option<String>> = Mutex::new(None);

thread_local! {
    /// Se a thread está dentro de uma chamada: o gancho de `panic` só cala o
    /// que acontece aqui, e deixa o resto do processo com o dele.
    static DENTRO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Roda o corpo de uma função exportada: converte um `panic` em
/// `CKR_GENERAL_ERROR`, com mensagem e local no registro, e anota a chamada.
pub(super) fn chamada(nome: &'static str, campos: Value, corpo: impl FnOnce() -> CK_RV) -> CK_RV {
    instalar_gancho();
    let inicio = Instant::now();
    let fora = DENTRO.replace(true);
    let rv = match panic::catch_unwind(AssertUnwindSafe(corpo)) {
        Ok(rv) => {
            let duracao = inicio.elapsed().as_millis();
            // Anotar nunca derruba a chamada que deveria explicar.
            let _ = panic::catch_unwind(|| anotar(nome, campos, rv, duracao, None));
            rv
        }
        Err(_) => {
            let duracao = inicio.elapsed().as_millis();
            let mensagem = trava(&PANICO).take().unwrap_or_default();
            let _ = panic::catch_unwind(|| {
                anotar(nome, campos, CKR_GENERAL_ERROR, duracao, Some(mensagem))
            });
            CKR_GENERAL_ERROR
        }
    };
    DENTRO.set(fora);
    rv
}

/// Um evento de dentro de uma operação (o bloco que vai ao HSM, a falha do
/// motor), gravado depois do anel.
pub(super) fn evento(tipo: &str, campos: Value) {
    descarregar(&mut trava(&REGISTRO)).evento(tipo, campos);
}

/// O registro deste processo, para o motor gravar no mesmo arquivo.
pub(super) fn diagnostico() -> Diagnostico {
    abrir(&mut trava(&REGISTRO))
}

fn abrir(registro: &mut Registro) -> Diagnostico {
    registro
        .diagnostico
        .get_or_insert_with(|| Diagnostico::abrir(&Caminhos::do_ambiente().diagnostico(), "modulo"))
        .clone()
}

/// Leva ao disco o que está no anel, e devolve o registro.
fn descarregar(registro: &mut Registro) -> Diagnostico {
    let diagnostico = abrir(registro);
    if registro.omitidas > 0 {
        diagnostico.evento("pkcs11_omitidas", json!({ "chamadas": registro.omitidas }));
        registro.omitidas = 0;
    }
    for (t, campos) in registro.contexto.drain(..) {
        diagnostico.evento_em(t, "pkcs11", campos);
    }
    diagnostico
}

fn anotar(nome: &str, campos: Value, rv: CK_RV, ms: u128, panico: Option<String>) {
    let importa = panico.is_some()
        || OPERACOES.contains(&nome)
        || !matches!(rv, CKR_OK | CKR_BUFFER_TOO_SMALL);
    let mut linha = Map::new();
    linha.insert("funcao".into(), json!(nome));
    if let Value::Object(campos) = campos {
        linha.extend(campos);
    }
    linha.insert("rv".into(), json!(nome_do_rv(rv)));
    linha.insert("ms".into(), json!(ms));
    if let Some(panico) = panico {
        linha.insert("panico".into(), json!(panico));
    }
    let mut registro = trava(&REGISTRO);
    if importa {
        descarregar(&mut registro).evento("pkcs11", Value::Object(linha));
    } else {
        if registro.contexto.len() == CONTEXTO {
            registro.contexto.pop_front();
            registro.omitidas += 1;
        }
        registro.contexto.push_back((agora(), Value::Object(linha)));
    }
}

/// Troca o gancho de `panic` uma vez por processo. Dentro de uma chamada, a
/// mensagem vai para o registro e não para o stderr do hospedeiro; fora,
/// segue para o gancho que já havia.
fn instalar_gancho() {
    static UMA_VEZ: Once = Once::new();
    UMA_VEZ.call_once(|| {
        let anterior = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !DENTRO.get() {
                return anterior(info);
            }
            let mensagem = info.payload_as_str().unwrap_or("sem mensagem");
            let texto = match info.location() {
                Some(l) => format!("{mensagem} ({}:{})", l.file(), l.line()),
                None => mensagem.to_string(),
            };
            *trava(&PANICO) = Some(texto);
        }));
    });
}

/// O mecanismo pelo nome, quando é um que se espera ver aqui.
pub(super) fn mecanismo(tipo: CK_MECHANISM_TYPE) -> String {
    let nome = match tipo {
        CKM_RSA_PKCS => "CKM_RSA_PKCS",
        CKM_RSA_X_509 => "CKM_RSA_X_509",
        CKM_RSA_PKCS_PSS => "CKM_RSA_PKCS_PSS",
        CKM_SHA1_RSA_PKCS => "CKM_SHA1_RSA_PKCS",
        CKM_SHA256_RSA_PKCS => "CKM_SHA256_RSA_PKCS",
        CKM_SHA384_RSA_PKCS => "CKM_SHA384_RSA_PKCS",
        CKM_SHA512_RSA_PKCS => "CKM_SHA512_RSA_PKCS",
        CKM_SHA256_RSA_PKCS_PSS => "CKM_SHA256_RSA_PKCS_PSS",
        CKM_SHA384_RSA_PKCS_PSS => "CKM_SHA384_RSA_PKCS_PSS",
        CKM_SHA512_RSA_PKCS_PSS => "CKM_SHA512_RSA_PKCS_PSS",
        CKM_ECDSA => "CKM_ECDSA",
        _ => return format!("0x{tipo:x}"),
    };
    nome.to_string()
}

/// O mecanismo de um ponteiro do hospedeiro, que pode ser nulo.
///
/// # Safety
///
/// `p` é nulo ou aponta para um `CK_MECHANISM`.
pub(super) unsafe fn mecanismo_de(p: *const CK_MECHANISM) -> Option<String> {
    unsafe { p.as_ref() }.map(|m| mecanismo(m.mechanism))
}

/// Os tipos dos atributos de um modelo, sem os valores: num modelo de busca o
/// valor pode ser o serial ou o titular.
///
/// # Safety
///
/// `modelo` é nulo ou aponta para `quantos` atributos.
pub(super) unsafe fn atributos(modelo: *const CK_ATTRIBUTE, quantos: CK_ULONG) -> Vec<String> {
    if modelo.is_null() {
        return Vec::new();
    }
    let n = (quantos as usize).min(ATRIBUTOS);
    unsafe { std::slice::from_raw_parts(modelo, n) }
        .iter()
        .map(|a| format!("0x{:x}", a.type_))
        .collect()
}

/// Tamanho e impressão digital de bytes que não podem ir ao registro, como o
/// que vai ser assinado: dá para casar com o pedido do motor sem ver o
/// conteúdo.
pub(super) fn impressao(dados: &[u8]) -> Value {
    let hash: String = sha256(dados)[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    json!({ "bytes": dados.len(), "sha256": hash })
}

fn nome_do_rv(rv: CK_RV) -> String {
    let nome = match rv {
        CKR_OK => "CKR_OK",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
        CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_CRYPTOKI_ALREADY_INITIALIZED => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        CKR_CRYPTOKI_NOT_INITIALIZED => "CKR_CRYPTOKI_NOT_INITIALIZED",
        CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_SESSION_PARALLEL_NOT_SUPPORTED => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
        CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",
        _ => return format!("0x{rv:x}"),
    };
    nome.to_string()
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_vira_erro_com_mensagem_e_local() {
        let dir = std::env::temp_dir().join(format!("remoteid-registro-{}", std::process::id()));
        let diagnostico = Diagnostico::abrir(&dir, "teste");
        let arquivo = diagnostico.caminho().unwrap().to_path_buf();
        trava(&REGISTRO).diagnostico = Some(diagnostico);

        let rv = chamada("C_Teste", json!({}), || panic!("estourou aqui"));
        assert_eq!(rv, CKR_GENERAL_ERROR);
        assert!(!DENTRO.get(), "a thread sai da chamada mesmo com panic");
        let registro = std::fs::read_to_string(&arquivo).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            registro.contains("estourou aqui (src/pkcs11/registro.rs:"),
            "{registro}"
        );
        assert!(
            registro.contains(r#""rv":"CKR_GENERAL_ERROR""#),
            "{registro}"
        );
    }

    #[test]
    fn nomes_conhecidos_e_o_resto_em_hexadecimal() {
        assert_eq!(nome_do_rv(CKR_PIN_LOCKED), "CKR_PIN_LOCKED");
        assert_eq!(nome_do_rv(0x8000_0001), "0x80000001");
        assert_eq!(mecanismo(CKM_RSA_PKCS_PSS), "CKM_RSA_PKCS_PSS");
        assert_eq!(mecanismo(0x1234), "0x1234");
    }

    #[test]
    fn impressao_nao_carrega_os_dados() {
        let v = impressao(b"conteudo secreto").to_string();
        assert!(!v.contains("conteudo"), "{v}");
        assert!(v.contains(r#""bytes":16"#), "{v}");
    }
}
