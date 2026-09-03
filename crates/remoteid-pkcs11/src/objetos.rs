//! Os objetos do token e seus atributos.
//!
//! Um objeto Cryptoki é, na prática, um saco de pares (tipo, bytes). Guardamos
//! exatamente isso: a serialização de cada valor já pronta, para que
//! `C_GetAttributeValue` seja só uma cópia de memória e não tenha de decidir
//! nada na hora.

use cryptoki_sys::*;

pub struct Atributo {
    pub tipo: CK_ATTRIBUTE_TYPE,
    pub valor: Vec<u8>,
}

pub struct Objeto {
    pub handle: CK_OBJECT_HANDLE,
    pub atributos: Vec<Atributo>,
}

/// `CK_TRUE`/`CK_FALSE` ocupam um byte (`CK_BBOOL`).
fn booleano(v: bool) -> Vec<u8> {
    vec![if v { CK_TRUE } else { CK_FALSE }]
}

/// Inteiros do Cryptoki (`CK_ULONG`, `CK_OBJECT_CLASS`, ...) vão no tamanho e na
/// ordem de bytes NATIVOS da plataforma, não em big-endian. É o que o
/// hospedeiro faz do outro lado ao ler o valor de volta.
fn ulong(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

impl Objeto {
    /// O `CKO_CERTIFICATE` X.509 do titular.
    ///
    /// `CKA_PRIVATE` é falso de propósito: o certificado é dado público, e
    /// marcá-lo como privado obrigaria o hospedeiro a fazer `C_Login` (isto é, a
    /// pedir o PIN) só para LISTAR o certificado. Como não há segredo aqui, o
    /// login fica reservado para a assinatura.
    pub fn certificado(
        der: Vec<u8>,
        subject: Vec<u8>,
        issuer: Vec<u8>,
        serial: Vec<u8>,
        id: Vec<u8>,
        rotulo: String,
    ) -> Objeto {
        Objeto {
            handle: HANDLE_CERTIFICADO,
            atributos: vec![
                Atributo {
                    tipo: CKA_CLASS,
                    valor: ulong(CKO_CERTIFICATE),
                },
                Atributo {
                    tipo: CKA_TOKEN,
                    valor: booleano(true),
                },
                Atributo {
                    tipo: CKA_PRIVATE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_MODIFIABLE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_LABEL,
                    valor: rotulo.into_bytes(),
                },
                Atributo {
                    tipo: CKA_CERTIFICATE_TYPE,
                    valor: ulong(CKC_X_509),
                },
                Atributo {
                    tipo: CKA_TRUSTED,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_CERTIFICATE_CATEGORY,
                    valor: ulong(CK_CERTIFICATE_CATEGORY_TOKEN_USER),
                },
                Atributo {
                    tipo: CKA_ID,
                    valor: id,
                },
                Atributo {
                    tipo: CKA_SUBJECT,
                    valor: subject,
                },
                Atributo {
                    tipo: CKA_ISSUER,
                    valor: issuer,
                },
                Atributo {
                    tipo: CKA_SERIAL_NUMBER,
                    valor: serial,
                },
                Atributo {
                    tipo: CKA_VALUE,
                    valor: der,
                },
            ],
        }
    }

    /// O objeto `CKO_PUBLIC_KEY` correspondente ao certificado.
    ///
    /// Redundante em relação ao certificado (o SPKI está lá), mas ferramenta
    /// séria — `p11tool --test-sign`, alguns caminhos do GnuTLS — procura o
    /// `CKO_PUBLIC_KEY` explicitamente e reclama quando não encontra. O custo
    /// é dois `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT` a mais e nada de segredo.
    pub fn chave_publica(
        modulo: Vec<u8>,
        expoente: Vec<u8>,
        id: Vec<u8>,
        rotulo: Vec<u8>,
    ) -> Objeto {
        Objeto {
            handle: HANDLE_CHAVE_PUBLICA,
            atributos: vec![
                Atributo {
                    tipo: CKA_CLASS,
                    valor: ulong(CKO_PUBLIC_KEY),
                },
                Atributo {
                    tipo: CKA_KEY_TYPE,
                    valor: ulong(CKK_RSA),
                },
                Atributo {
                    tipo: CKA_TOKEN,
                    valor: booleano(true),
                },
                Atributo {
                    tipo: CKA_PRIVATE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_MODIFIABLE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_LABEL,
                    valor: rotulo,
                },
                Atributo {
                    tipo: CKA_ID,
                    valor: id,
                },
                Atributo {
                    tipo: CKA_VERIFY,
                    valor: booleano(true),
                },
                Atributo {
                    tipo: CKA_ENCRYPT,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_MODULUS,
                    valor: modulo,
                },
                Atributo {
                    tipo: CKA_PUBLIC_EXPONENT,
                    valor: expoente,
                },
            ],
        }
    }

    /// O objeto `CKO_PRIVATE_KEY` correspondente ao certificado.
    ///
    /// - `CKA_ID` e `CKA_LABEL` batem com os do certificado: é assim que o NSS
    ///   e o poppler pareiam certificado e chave.
    /// - `CKA_MODULUS` e `CKA_PUBLIC_EXPONENT` **vêm do certificado** (do SPKI),
    ///   não da chave, para evitar qualquer chance de o par não fechar.
    /// - `CKA_SENSITIVE = TRUE` e `CKA_EXTRACTABLE = FALSE`: a chave (mesmo em
    ///   modo de teste, para o hospedeiro se comportar como em produção) não
    ///   sai daqui. `C_GetAttributeValue` sobre um atributo sensível deste
    ///   objeto vai receber `CKR_ATTRIBUTE_SENSITIVE`.
    /// - `CKA_ALWAYS_AUTHENTICATE = FALSE`: em produção o PIN+OTP entra por
    ///   fora (via daemon/UI), então não peço reautenticação em cada assinatura.
    pub fn chave_privada(
        modulo: Vec<u8>,
        expoente: Vec<u8>,
        id: Vec<u8>,
        rotulo: Vec<u8>,
    ) -> Objeto {
        Objeto {
            handle: HANDLE_CHAVE_PRIVADA,
            atributos: vec![
                Atributo {
                    tipo: CKA_CLASS,
                    valor: ulong(CKO_PRIVATE_KEY),
                },
                Atributo {
                    tipo: CKA_KEY_TYPE,
                    valor: ulong(CKK_RSA),
                },
                Atributo {
                    tipo: CKA_TOKEN,
                    valor: booleano(true),
                },
                // `CKA_PRIVATE = false`: o módulo não exige login (a autenticação
                // real é no app, no C_Sign), então o objeto é visível em sessão
                // pública. `CKA_SENSITIVE` abaixo continua protegendo o MATERIAL
                // da chave — o que não sai daqui é o expoente privado, não a
                // existência do objeto. Ver o comentário de flags em C_GetTokenInfo.
                Atributo {
                    tipo: CKA_PRIVATE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_MODIFIABLE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_LABEL,
                    valor: rotulo,
                },
                Atributo {
                    tipo: CKA_ID,
                    valor: id,
                },
                Atributo {
                    tipo: CKA_SENSITIVE,
                    valor: booleano(true),
                },
                Atributo {
                    tipo: CKA_EXTRACTABLE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_ALWAYS_AUTHENTICATE,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_SIGN,
                    valor: booleano(true),
                },
                Atributo {
                    tipo: CKA_SIGN_RECOVER,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_DECRYPT,
                    valor: booleano(false),
                },
                Atributo {
                    tipo: CKA_MODULUS,
                    valor: modulo,
                },
                Atributo {
                    tipo: CKA_PUBLIC_EXPONENT,
                    valor: expoente,
                },
            ],
        }
    }

    /// Atributos sensíveis (`CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1` etc.) que
    /// existem no objeto conceitual mas não podem ser lidos.
    ///
    /// Não é lista definitiva do PKCS#11 — só o que a especificação marca como
    /// sensível para RSA e que faz sentido este módulo defender ativamente.
    pub fn e_sensivel(&self, tipo: CK_ATTRIBUTE_TYPE) -> bool {
        self.atributo(CKA_CLASS)
            .is_some_and(|a| a.valor == CKO_PRIVATE_KEY.to_ne_bytes())
            && matches!(
                tipo,
                CKA_VALUE
                    | CKA_PRIVATE_EXPONENT
                    | CKA_PRIME_1
                    | CKA_PRIME_2
                    | CKA_EXPONENT_1
                    | CKA_EXPONENT_2
                    | CKA_COEFFICIENT,
            )
    }

    pub fn atributo(&self, tipo: CK_ATTRIBUTE_TYPE) -> Option<&Atributo> {
        self.atributos.iter().find(|a| a.tipo == tipo)
    }

    /// Regra de casamento do `C_FindObjects`: TODO atributo do template tem de
    /// existir no objeto e bater byte a byte. Template vazio casa com tudo.
    pub fn casa(&self, gabarito: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        gabarito
            .iter()
            .all(|(tipo, valor)| match self.atributo(*tipo) {
                Some(a) => a.valor == *valor,
                None => false,
            })
    }
}

/// Handles são opacos para o hospedeiro; o que não pode é ser zero
/// (`CK_INVALID_HANDLE`).
pub const HANDLE_CERTIFICADO: CK_OBJECT_HANDLE = 1;
pub const HANDLE_CHAVE_PRIVADA: CK_OBJECT_HANDLE = 2;
pub const HANDLE_CHAVE_PUBLICA: CK_OBJECT_HANDLE = 3;

#[cfg(test)]
mod tests {
    use super::*;

    fn exemplo() -> Objeto {
        Objeto::certificado(
            vec![0x30, 0x82],
            vec![0x30, 0x10],
            vec![0x30, 0x11],
            vec![0x02, 0x01, 0x2a],
            vec![0xaa; 20],
            "FULANO".into(),
        )
    }

    #[test]
    fn template_vazio_casa_com_tudo() {
        assert!(exemplo().casa(&[]));
    }

    #[test]
    fn busca_por_classe_casa_com_o_certificado() {
        let alvo = vec![(CKA_CLASS, CKO_CERTIFICATE.to_ne_bytes().to_vec())];
        assert!(exemplo().casa(&alvo));
    }

    #[test]
    fn busca_por_outra_classe_nao_casa() {
        // É o que o NSS faz ao procurar chaves privadas: não pode vir o
        // certificado no lugar.
        let alvo = vec![(CKA_CLASS, CKO_PRIVATE_KEY.to_ne_bytes().to_vec())];
        assert!(!exemplo().casa(&alvo));
    }

    #[test]
    fn atributo_ausente_no_objeto_derruba_o_casamento() {
        let alvo = vec![(CKA_MODULUS, vec![1, 2, 3])];
        assert!(!exemplo().casa(&alvo));
    }

    #[test]
    fn booleano_ocupa_um_byte_so() {
        assert_eq!(booleano(true), vec![1u8]);
        assert_eq!(booleano(false), vec![0u8]);
    }
}
