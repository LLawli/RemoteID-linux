//! O campo `algorithm` do `requestHashSessionSignature`.
//!
//! Medido no servidor real (sondagens de 05/09 e 22/09/2026):
//!
//! | `algorithm` | o `hash` enviado é       | o HSM faz                          |
//! |-------------|--------------------------|------------------------------------|
//! | `"SHA256"`  | o SHA-256, 32 bytes      | DigestInfo(SHA-256) e padding      |
//! | `""`        | o bloco pronto           | só o padding PKCS#1 v1.5           |
//!
//! O modo cru é o do `CKM_RSA_PKCS`, e é o que permite assinar MD5withRSA para
//! o PJeOffice. Não existe RSASSA-PSS nem operação sem padding no servidor:
//! todos os outros nomes testados voltaram recusados.

/// O teto do PKCS#1 v1.5 para RSA-2048 (`k - 11`). O servidor impõe o mesmo:
/// 245 bytes assinam, 246 voltam com "Invalid input data size.(1011)".
pub const MAX_BLOCO_CRU: usize = 245;

const BYTES_SHA256: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algoritmo {
    #[default]
    Sha256,
    Cru,
}

impl Algoritmo {
    /// O valor exato do campo. O cru é a string vazia, presente no corpo.
    pub const fn nome(self) -> &'static str {
        match self {
            Algoritmo::Sha256 => "SHA256",
            Algoritmo::Cru => "",
        }
    }

    pub fn do_nome(nome: &str) -> Option<Algoritmo> {
        [Algoritmo::Sha256, Algoritmo::Cru]
            .into_iter()
            .find(|a| a.nome() == nome)
    }

    /// Se o servidor aceita assinar `dados` neste modo. Recusar aqui poupa uma
    /// requisição e, no meio de uma assinatura, o OTP de quem o digitou.
    pub fn aceita(self, dados: &[u8]) -> bool {
        match self {
            Algoritmo::Sha256 => dados.len() == BYTES_SHA256,
            Algoritmo::Cru => (1..=MAX_BLOCO_CRU).contains(&dados.len()),
        }
    }
}
