//! O token: o que o módulo mostra, montado do estado em disco.
//!
//! Montar o token não vai à rede, não pede nada à pessoa e não grava nada. O
//! módulo é carregado a cada conexão ao `p11-kit server` do Âncora, inclusive
//! pela sonda da supervisão a cada 10 s, e listar tokens tem de responder na
//! hora.

use cryptoki_sys::*;
use rsa::RsaPublicKey;
use rsa::traits::PublicKeyParts;

use super::objetos::{HANDLE_CERTIFICADO, Objeto};
use crate::cripto::de_b64;
use crate::estado::Estado;
use crate::protocolo::Certificado;
use crate::x509;

/// O único slot. Diferente de zero: há software que trata `0` como "nenhum".
pub const ID_SLOT: CK_SLOT_ID = 1;

pub struct Token {
    /// O certificado da carteira que o token mostra, e com o qual o `C_Sign`
    /// assina.
    pub certificado: Certificado,
    pub objetos: Vec<Objeto>,
    pub publica: RsaPublicKey,
}

impl Token {
    /// O token do certificado ativo. `None` enquanto a conta não foi
    /// preparada, ou se a carteira não trouxe um certificado RSA legível: o
    /// slot existe, vazio.
    pub fn do_estado(estado: &Estado) -> Option<Token> {
        let certificado = estado.certificado()?;
        let der = de_b64(certificado.base64.as_deref()?)?;
        Token::do_certificado(certificado.clone(), &der).ok()
    }

    pub fn do_certificado(certificado: Certificado, der: &[u8]) -> Result<Token, String> {
        let campos = x509::ler(der)?;
        let publica = campos
            .publica
            .clone()
            .ok_or("a chave do certificado não é RSA")?;
        let rotulo = campos
            .nome
            .clone()
            .unwrap_or_else(|| format!("RemoteID {}", certificado.serial_number));
        // `to_bytes_be` tira os zeros à esquerda, como o Cryptoki manda.
        let modulo = publica.n().to_bytes_be();
        let expoente = publica.e().to_bytes_be();
        let objetos = vec![
            Objeto::certificado(
                HANDLE_CERTIFICADO,
                der,
                &campos,
                &rotulo,
                CK_CERTIFICATE_CATEGORY_TOKEN_USER,
            ),
            Objeto::chave_privada(&campos, &rotulo, &modulo, &expoente),
            Objeto::chave_publica(&campos, &rotulo, &modulo, &expoente),
        ];
        Ok(Token {
            certificado,
            objetos,
            publica,
        })
    }

    /// O tamanho de toda assinatura e cifra: o do módulo da chave.
    pub fn bytes_bloco(&self) -> usize {
        self.publica.size()
    }

    pub fn objeto(&self, handle: CK_OBJECT_HANDLE) -> Option<&Objeto> {
        self.objetos.iter().find(|o| o.handle == handle)
    }

    pub fn buscar(&self, gabarito: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Vec<CK_OBJECT_HANDLE> {
        self.objetos
            .iter()
            .filter(|o| o.casa(gabarito))
            .map(|o| o.handle)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::objetos::{HANDLE_CHAVE_PRIVADA, HANDLE_CHAVE_PUBLICA, ulong};
    use super::*;
    use crate::cripto::b64;

    const TITULAR: &[u8] = include_bytes!("../../tests/mock/fake-cert.der");

    fn token() -> Token {
        let certificado = Certificado::do_key_name("SERIE;CN=AC", Some(b64(TITULAR))).unwrap();
        Token::do_estado(&Estado {
            certificados: vec![certificado],
            ..Estado::default()
        })
        .unwrap()
    }

    #[test]
    fn sem_carteira_o_slot_fica_vazio() {
        assert!(Token::do_estado(&Estado::default()).is_none());
        let sem_der = Certificado::do_key_name("SERIE;CN=AC", None).unwrap();
        assert!(
            Token::do_estado(&Estado {
                certificados: vec![sem_der],
                ..Estado::default()
            })
            .is_none()
        );
    }

    #[test]
    fn certificado_e_chaves_pareiam_pelo_id_e_pelo_rotulo() {
        let t = token();
        let id = t
            .objeto(HANDLE_CERTIFICADO)
            .unwrap()
            .atributo(CKA_ID)
            .unwrap();
        let mut par = t.buscar(&[(CKA_ID, id.to_vec())]);
        par.sort();
        assert_eq!(
            par,
            [
                HANDLE_CERTIFICADO,
                HANDLE_CHAVE_PRIVADA,
                HANDLE_CHAVE_PUBLICA
            ]
        );
        for h in par {
            assert_eq!(
                t.objeto(h).unwrap().atributo(CKA_LABEL),
                Some(&b"TESTE DESKTOPID:00000000000"[..])
            );
        }
    }

    #[test]
    fn busca_por_classe_e_o_que_o_nss_faz() {
        let t = token();
        let privadas = t.buscar(&[(CKA_CLASS, ulong(CKO_PRIVATE_KEY))]);
        assert_eq!(privadas, [HANDLE_CHAVE_PRIVADA]);
        assert_eq!(t.buscar(&[]).len(), 3);
        assert!(t.buscar(&[(CKA_MODULUS, vec![1, 2, 3])]).is_empty());
    }

    #[test]
    fn a_chave_privada_nao_entrega_o_material() {
        let t = token();
        let privada = t.objeto(HANDLE_CHAVE_PRIVADA).unwrap();
        assert!(privada.e_sensivel(CKA_PRIVATE_EXPONENT));
        assert!(privada.e_sensivel(CKA_VALUE));
        assert!(!privada.e_sensivel(CKA_MODULUS));
        // No certificado, `CKA_VALUE` é o DER, e é público.
        assert!(!t.objeto(HANDLE_CERTIFICADO).unwrap().e_sensivel(CKA_VALUE));
        assert_eq!(t.bytes_bloco(), 256);
    }
}
