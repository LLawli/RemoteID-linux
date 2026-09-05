//! O campo `algorithm` do `requestHashSessionSignature`: o que o servidor
//! aceita e o que cada valor faz com o `hash` enviado.
//!
//! Medido ao vivo em 05/09/2026 (sondagem de cinco casos numa única sessão,
//! registrada na issue #10). PKCS#1 v1.5 é determinístico, e a assinatura do
//! caso "`""` + DigestInfo(SHA-256)" saiu byte a byte igual à do caso
//! "`SHA256` + hash", o que fecha a semântica dos dois modos:
//!
//! | `algorithm` | o `hash` enviado é…              | o HSM faz…                              |
//! |-------------|----------------------------------|-----------------------------------------|
//! | `"SHA256"`  | o hash cru, 32 bytes             | embrulha em DigestInfo(SHA-256) + padding |
//! | `""`        | o bloco pronto (DigestInfo ou não) | SÓ o padding PKCS#1 v1.5                |
//!
//! O modo cru é o que o módulo PKCS#11 oficial usa para `CKM_RSA_PKCS`, e é o
//! que permite assinar `MD5withRSA` para o PJeOffice: o `DigestInfo(MD5)` vai
//! inteiro, e volta assinado. O servidor também honra `"SHA1"` por nome e
//! recusa `"MD5"` por nome ("Erro ao gerar assinatura RSA."); nenhum dos dois
//! é usado aqui, então não são modelados.
//!
//! Este é o ÚNICO lugar com os literais do campo. O socket interno os carrega
//! como string opaca e converte na borda do daemon com [`Algoritmo::do_nome`].

use remoteid_cripto::MAX_BLOCO_PKCS1_V15;
use remoteid_tipos::{Error, Result};

/// Tamanho do hash SHA-256, em bytes: o único que o modo `SHA256` aceita.
const BYTES_SHA256: usize = 32;

/// O que o servidor deve fazer com os bytes enviados no `hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algoritmo {
    /// `"SHA256"`: os bytes são o hash; o HSM embrulha em DigestInfo e assina.
    /// É o caminho de produção original, e o padrão quando nada é dito.
    #[default]
    Sha256,
    /// `""`: os bytes são o bloco pronto; o HSM só aplica o padding.
    Cru,
}

impl Algoritmo {
    /// O literal exato do campo `algorithm`. `Cru` é a string VAZIA, presente
    /// no JSON, nunca omitida: foi assim que a sondagem provou o modo.
    pub const fn nome(self) -> &'static str {
        match self {
            Algoritmo::Sha256 => "SHA256",
            Algoritmo::Cru => "",
        }
    }

    /// O inverso de [`Self::nome`]. `None` para qualquer outro valor: o
    /// servidor até aceita `"SHA1"`, mas este cliente não o emite.
    pub fn do_nome(nome: &str) -> Option<Algoritmo> {
        [Algoritmo::Sha256, Algoritmo::Cru]
            .into_iter()
            .find(|a| a.nome() == nome)
    }

    /// A regra de tamanho do bloco, uma só para o daemon, o motor e quem mais
    /// receber bytes para assinar.
    ///
    /// - `Sha256`: exatamente 32 bytes, o hash.
    /// - `Cru`: de 1 a `k - 11` bytes (245 para RSA-2048), o teto do PKCS#1
    ///   v1.5. Só blocos de 34 e 51 bytes foram sondados; se o servidor tiver
    ///   um teto menor, o diag registra a recusa.
    pub fn validar(self, dados: &[u8]) -> Result<()> {
        match self {
            Algoritmo::Sha256 if dados.len() != BYTES_SHA256 => Err(Error::uso(format!(
                "o digest tem de ser SHA-256 ({BYTES_SHA256} bytes); veio com {}",
                dados.len()
            ))),
            Algoritmo::Cru if dados.is_empty() => {
                Err(Error::uso("o bloco a assinar no modo cru está vazio"))
            }
            Algoritmo::Cru if dados.len() > MAX_BLOCO_PKCS1_V15 => Err(Error::uso(format!(
                "o bloco a assinar no modo cru tem {} bytes; o PKCS#1 v1.5 aceita até {MAX_BLOCO_PKCS1_V15}",
                dados.len()
            ))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_literais_sao_os_que_o_servidor_aceitou() {
        // Testes de ouro: mudar estes valores é mudar o que vai no fio.
        assert_eq!(Algoritmo::Sha256.nome(), "SHA256");
        assert_eq!(Algoritmo::Cru.nome(), "");
    }

    #[test]
    fn do_nome_e_o_inverso_de_nome() {
        for a in [Algoritmo::Sha256, Algoritmo::Cru] {
            assert_eq!(Algoritmo::do_nome(a.nome()), Some(a));
        }
        // O servidor honra SHA1 por nome, mas este cliente não emite: um
        // pedido assim no socket é entrada inválida, não um modo escondido.
        assert_eq!(Algoritmo::do_nome("SHA1"), None);
        assert_eq!(Algoritmo::do_nome("MD5"), None);
        assert_eq!(Algoritmo::do_nome("sha256"), None, "sensível a caixa");
    }

    #[test]
    fn o_padrao_e_sha256() {
        // Um módulo PKCS#11 antigo, que não manda o campo, continua no
        // caminho de produção original.
        assert_eq!(Algoritmo::default(), Algoritmo::Sha256);
    }

    #[test]
    fn sha256_exige_exatamente_32_bytes() {
        assert!(Algoritmo::Sha256.validar(&[0u8; 32]).is_ok());
        assert!(Algoritmo::Sha256.validar(&[0u8; 20]).is_err());
        assert!(Algoritmo::Sha256.validar(&[0u8; 51]).is_err());
        assert!(Algoritmo::Sha256.validar(&[]).is_err());
    }

    #[test]
    fn cru_aceita_de_um_ate_o_teto_do_pkcs1() {
        assert!(
            Algoritmo::Cru.validar(&[0u8; 34]).is_ok(),
            "DigestInfo(MD5)"
        );
        assert!(
            Algoritmo::Cru.validar(&[0u8; 51]).is_ok(),
            "DigestInfo(SHA-256)"
        );
        assert!(Algoritmo::Cru.validar(&[0u8; 1]).is_ok());
        assert!(Algoritmo::Cru.validar(&[0u8; 245]).is_ok());
        assert!(Algoritmo::Cru.validar(&[0u8; 246]).is_err());
        assert!(Algoritmo::Cru.validar(&[]).is_err());
    }

    #[test]
    fn o_erro_de_validacao_e_de_uso() {
        // É o que faz o daemon responder EntradaInvalida, e não erro interno.
        assert!(matches!(
            Algoritmo::Sha256.validar(&[0u8; 20]),
            Err(Error::Uso(_))
        ));
    }
}
