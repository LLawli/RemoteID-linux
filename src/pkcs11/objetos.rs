//! Os objetos do token e seus atributos.
//!
//! Um objeto Cryptoki é um saco de pares (tipo, bytes). Cada valor fica já
//! serializado, para que `C_GetAttributeValue` seja só uma cópia.

use cryptoki_sys::*;

use crate::x509::Campos;

/// Handles são opacos para o hospedeiro; o que não pode é zero
/// (`CK_INVALID_HANDLE`).
pub const HANDLE_CERTIFICADO: CK_OBJECT_HANDLE = 1;
pub const HANDLE_CHAVE_PRIVADA: CK_OBJECT_HANDLE = 2;
pub const HANDLE_CHAVE_PUBLICA: CK_OBJECT_HANDLE = 3;

pub type Atributo = (CK_ATTRIBUTE_TYPE, Vec<u8>);

pub struct Objeto {
    pub handle: CK_OBJECT_HANDLE,
    pub atributos: Vec<Atributo>,
}

fn booleano(v: bool) -> Vec<u8> {
    vec![if v { CK_TRUE } else { CK_FALSE }]
}

/// Os inteiros do Cryptoki vão no tamanho e na ordem de bytes nativos, que é
/// como o hospedeiro os lê de volta.
pub fn ulong(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

/// O que todo objeto deste token tem: ele é de leitura, e nada nele é
/// privado. Marcar o certificado ou a chave como privados obrigaria o
/// hospedeiro a fazer `C_Login` só para listá-los, e o login daqui não
/// autentica nada: o PIN e o OTP são pedidos no `C_Sign`.
fn comuns(classe: CK_OBJECT_CLASS, rotulo: &str, id: &[u8]) -> Vec<Atributo> {
    vec![
        (CKA_CLASS, ulong(classe)),
        (CKA_TOKEN, booleano(true)),
        (CKA_PRIVATE, booleano(false)),
        (CKA_MODIFIABLE, booleano(false)),
        (CKA_LABEL, rotulo.as_bytes().to_vec()),
        (CKA_ID, id.to_vec()),
    ]
}

/// O que as duas chaves têm igual: RSA, gerada fora daqui, e sem derivação.
fn de_chave() -> [Atributo; 3] {
    [
        (CKA_KEY_TYPE, ulong(CKK_RSA)),
        (CKA_LOCAL, booleano(false)),
        (CKA_DERIVE, booleano(false)),
    ]
}

impl Objeto {
    /// Um `CKO_CERTIFICATE` X.509. O do titular é `TOKEN_USER`; o de uma
    /// autoridade da cadeia é `AUTHORITY`, que o NSS classifica como AC, e
    /// existe para o hospedeiro montar a cadeia sem ir à rede: o SunPKCS11
    /// procura o certificado cujo `CKA_SUBJECT` é o emissor do anterior.
    ///
    /// `CKA_TRUSTED` é falso nos dois: confiar numa raiz é decisão do
    /// hospedeiro, não de um token que a baixou por HTTP.
    pub fn certificado(
        handle: CK_OBJECT_HANDLE,
        der: &[u8],
        campos: &Campos,
        rotulo: &str,
        categoria: CK_ULONG,
    ) -> Objeto {
        let mut atributos = comuns(CKO_CERTIFICATE, rotulo, &campos.id);
        atributos.extend([
            (CKA_CERTIFICATE_TYPE, ulong(CKC_X_509)),
            (CKA_TRUSTED, booleano(false)),
            (CKA_CERTIFICATE_CATEGORY, ulong(categoria)),
            (CKA_SUBJECT, campos.subject.clone()),
            (CKA_ISSUER, campos.issuer.clone()),
            (CKA_SERIAL_NUMBER, campos.serial.clone()),
            (CKA_VALUE, der.to_vec()),
        ]);
        Objeto { handle, atributos }
    }

    /// O `CKO_PUBLIC_KEY` do certificado. Redundante com o SPKI, mas o
    /// `p11tool --test-sign` e caminhos do GnuTLS o procuram e reclamam quando
    /// não acham.
    ///
    /// `CKA_ENCRYPT` acompanha o `CKF_ENCRYPT` do `CKM_RSA_PKCS`: ver
    /// `C_GetMechanismInfo`.
    pub fn chave_publica(campos: &Campos, rotulo: &str, modulo: &[u8], expoente: &[u8]) -> Objeto {
        let mut atributos = comuns(CKO_PUBLIC_KEY, rotulo, &campos.id);
        atributos.extend(de_chave());
        atributos.extend([
            (CKA_VERIFY, booleano(true)),
            (CKA_VERIFY_RECOVER, booleano(false)),
            (CKA_ENCRYPT, booleano(true)),
            (CKA_WRAP, booleano(false)),
            (CKA_MODULUS_BITS, ulong(modulo.len() as CK_ULONG * 8)),
            (CKA_MODULUS, modulo.to_vec()),
            (CKA_PUBLIC_EXPONENT, expoente.to_vec()),
        ]);
        Objeto {
            handle: HANDLE_CHAVE_PUBLICA,
            atributos,
        }
    }

    /// O `CKO_PRIVATE_KEY`: o cabo que o hospedeiro segura para assinar. A
    /// chave de verdade está no HSM da Certisign.
    ///
    /// - `CKA_ID` e `CKA_LABEL` iguais aos do certificado: é assim que o NSS e
    ///   o poppler pareiam os dois.
    /// - Módulo e expoente vêm do certificado, para o par fechar byte a byte.
    /// - Sensível e não extraível, como num token de verdade.
    /// - `CKA_ALWAYS_AUTHENTICATE` falso: o PIN e o OTP entram pelo diálogo,
    ///   não por um `C_Login` a cada assinatura.
    pub fn chave_privada(campos: &Campos, rotulo: &str, modulo: &[u8], expoente: &[u8]) -> Objeto {
        let mut atributos = comuns(CKO_PRIVATE_KEY, rotulo, &campos.id);
        atributos.extend(de_chave());
        atributos.extend([
            (CKA_SENSITIVE, booleano(true)),
            (CKA_ALWAYS_SENSITIVE, booleano(true)),
            (CKA_EXTRACTABLE, booleano(false)),
            (CKA_NEVER_EXTRACTABLE, booleano(true)),
            (CKA_UNWRAP, booleano(false)),
            (CKA_ALWAYS_AUTHENTICATE, booleano(false)),
            (CKA_SIGN, booleano(true)),
            (CKA_SIGN_RECOVER, booleano(false)),
            (CKA_DECRYPT, booleano(false)),
            (CKA_MODULUS, modulo.to_vec()),
            (CKA_PUBLIC_EXPONENT, expoente.to_vec()),
        ]);
        Objeto {
            handle: HANDLE_CHAVE_PRIVADA,
            atributos,
        }
    }

    pub fn atributo(&self, tipo: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        self.atributos
            .iter()
            .find(|(t, _)| *t == tipo)
            .map(|(_, v)| v.as_slice())
    }

    pub fn classe(&self) -> Option<CK_OBJECT_CLASS> {
        Some(CK_OBJECT_CLASS::from_ne_bytes(
            self.atributo(CKA_CLASS)?.try_into().ok()?,
        ))
    }

    /// Os atributos de chave privada RSA que a especificação marca como
    /// sensíveis. Ler um deles é `CKR_ATTRIBUTE_SENSITIVE`, não "não existe".
    pub fn e_sensivel(&self, tipo: CK_ATTRIBUTE_TYPE) -> bool {
        self.classe() == Some(CKO_PRIVATE_KEY)
            && matches!(
                tipo,
                CKA_VALUE
                    | CKA_PRIVATE_EXPONENT
                    | CKA_PRIME_1
                    | CKA_PRIME_2
                    | CKA_EXPONENT_1
                    | CKA_EXPONENT_2
                    | CKA_COEFFICIENT
            )
    }

    /// A regra do `C_FindObjects`: todo atributo do gabarito tem de existir no
    /// objeto e bater byte a byte. Gabarito vazio casa com tudo.
    pub fn casa(&self, gabarito: &[Atributo]) -> bool {
        gabarito
            .iter()
            .all(|(tipo, valor)| self.atributo(*tipo) == Some(valor.as_slice()))
    }
}
