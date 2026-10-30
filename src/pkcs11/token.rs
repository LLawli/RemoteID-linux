//! O token: o que o módulo mostra, montado do estado em disco.
//!
//! Montar o token não vai à rede, não pede nada à pessoa e não grava nada. O
//! módulo é carregado a cada conexão ao `p11-kit server` do Âncora, inclusive
//! pela sonda da supervisão a cada 10 s, e listar tokens tem de responder na
//! hora.

use cryptoki_sys::*;
use rsa::RsaPublicKey;
use rsa::traits::PublicKeyParts;

use super::objetos::{HANDLE_CERTIFICADO, HANDLE_PRIMEIRA_AUTORIDADE, Objeto};
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
        // Os objetos do titular primeiro: há hospedeiro que pega o primeiro
        // certificado de uma busca e o toma pelo do titular.
        let mut objetos = vec![
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
        // Uma autoridade ilegível fica de fora sem derrubar o titular.
        let autoridades = certificado
            .cadeia
            .iter()
            .filter_map(|b| de_b64(b))
            .filter_map(|der| Some((x509::ler(&der).ok()?, der)));
        for ((campos, der), handle) in autoridades.zip(HANDLE_PRIMEIRA_AUTORIDADE..) {
            let rotulo = campos
                .nome
                .clone()
                .unwrap_or_else(|| "Autoridade certificadora".into());
            objetos.push(Objeto::certificado(
                handle,
                &der,
                &campos,
                &rotulo,
                CK_CERTIFICATE_CATEGORY_AUTHORITY,
            ));
        }
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
    const AC: &str = include_str!("../../tests/mock/fake-ac.pem");
    const RAIZ: &str = include_str!("../../tests/mock/fake-ac-raiz.pem");

    /// O DER de um PEM de um certificado só.
    fn der(pem: &str) -> Vec<u8> {
        let corpo: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        crate::cripto::de_b64(&corpo).unwrap()
    }

    fn token() -> Token {
        let mut certificado = Certificado::do_key_name("SERIE;CN=AC", Some(b64(TITULAR))).unwrap();
        certificado.cadeia = vec![b64(&der(AC)), "lixo".into(), b64(&der(RAIZ))];
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
        assert_eq!(t.buscar(&[]).len(), 5);
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

    fn atributo(t: &Token, h: CK_OBJECT_HANDLE, tipo: CK_ATTRIBUTE_TYPE) -> Vec<u8> {
        t.objeto(h).unwrap().atributo(tipo).unwrap().to_vec()
    }

    #[test]
    fn a_cadeia_se_percorre_pelo_subject_como_o_sunpkcs11_faz() {
        // O `P11KeyStore.loadChain`: do certificado final, procura o
        // certificado cujo CKA_SUBJECT é o emissor do anterior, até a
        // autoassinada. A autoridade ilegível ficou de fora sem furar a
        // sequência de handles.
        let t = token();
        let classe = (CKA_CLASS, ulong(CKO_CERTIFICATE));
        let mut atual = HANDLE_CERTIFICADO;
        let mut caminho = vec![];
        while atributo(&t, atual, CKA_ISSUER) != atributo(&t, atual, CKA_SUBJECT) {
            let emissor = (CKA_SUBJECT, atributo(&t, atual, CKA_ISSUER));
            let [proximo] = t.buscar(&[classe.clone(), emissor])[..] else {
                panic!("um emissor por passo");
            };
            atual = proximo;
            caminho.push(atual);
        }
        assert_eq!(
            caminho,
            [HANDLE_PRIMEIRA_AUTORIDADE, HANDLE_PRIMEIRA_AUTORIDADE + 1]
        );
    }

    #[test]
    fn as_autoridades_nao_pareiam_com_a_chave() {
        let t = token();
        let id_titular = atributo(&t, HANDLE_CERTIFICADO, CKA_ID);
        for h in [HANDLE_PRIMEIRA_AUTORIDADE, HANDLE_PRIMEIRA_AUTORIDADE + 1] {
            assert_eq!(
                atributo(&t, h, CKA_CERTIFICATE_CATEGORY),
                ulong(CK_CERTIFICATE_CATEGORY_AUTHORITY)
            );
            assert_ne!(atributo(&t, h, CKA_ID), id_titular);
        }
        assert_eq!(
            atributo(&t, HANDLE_PRIMEIRA_AUTORIDADE, CKA_LABEL),
            b"AC TESTE DESKTOPID"
        );
        let certificados = t.buscar(&[(CKA_CLASS, ulong(CKO_CERTIFICATE))]);
        assert_eq!(certificados[0], HANDLE_CERTIFICADO);
    }
}
