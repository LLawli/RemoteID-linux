//! Serialização canônica do corpo, que é o que a assinatura do Bearer cobre.
//!
//! Os endpoints de OPERAÇÃO do RemoteID (carteira, statusCelular, tokensessao,
//! requestHashSessionSignature) não autenticam com o JWT do login. O header é
//!
//! ```text
//! Authorization: Bearer <base64( RSA_sign_PKCS1( SHA256( canonical(corpo) ) ) )>
//! ```
//!
//! assinado com a chave privada da instalação. A regra do `canonical` saiu da
//! decompilação de `FUN_10002515b` no binário oficial de macOS e das funções de
//! tipo do jsoncpp em volta dela (`isString`, `isBool`, `isNumeric`):
//!
//! - objeto: chaves em ORDEM ALFABÉTICA; concatena o resultado de cada valor
//! - string: escreve o valor
//! - número: escreve o número
//! - bool `true`: escreve o **NOME DA CHAVE** (não a palavra "true")
//! - bool `false` e null: não escrevem nada
//! - array/objeto aninhado: recursão
//!
//! A regra do bool é a parte contraintuitiva, e foi o que corrompeu a assinatura
//! do `tokensessao` enquanto `push:false` era serializado como `"false"`.
//!
//! Consequência prática, aproveitada em [`crate::protocol`]: na canônica, uma
//! string VAZIA e uma chave AUSENTE produzem exatamente o mesmo resultado. Dá
//! para mandar `"pin":""` (paridade de JSON com o app oficial) sem alterar em
//! nada a assinatura.

use serde_json::Value;

/// Serializa `body` na forma canônica que a assinatura do Bearer cobre.
pub fn canonical(body: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, body, None);
    out
}

/// `key` é o nome sob o qual `node` aparece; só importa para o bool `true`,
/// que escreve o próprio nome da chave. Elementos de array não têm chave.
fn write_value(out: &mut String, node: &Value, key: Option<&str>) {
    match node {
        Value::Object(map) => {
            // BTreeMap-like: ordenamos explicitamente para não depender da
            // feature `preserve_order` do serde_json estar ligada ou não.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                write_value(out, &map[k], Some(k));
            }
        }
        Value::Array(items) => {
            for item in items {
                write_value(out, item, None);
            }
        }
        Value::Bool(true) => {
            // O nome da chave, não "true". Num array um bool não tem chave e
            // portanto não contribui com nada.
            if let Some(k) = key {
                out.push_str(k);
            }
        }
        Value::Bool(false) | Value::Null => {}
        Value::String(s) => out.push_str(s),
        Value::Number(n) => out.push_str(&n.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn carteira_e_so_o_momento() {
        // O corpo mais simples do protocolo, e o primeiro que passou ao vivo.
        assert_eq!(canonical(&json!({"momento": "1788393921"})), "1788393921");
    }

    #[test]
    fn chaves_saem_em_ordem_alfabetica_nao_de_insercao() {
        let body = json!({"zeta": "Z", "alfa": "A", "meio": "M"});
        assert_eq!(canonical(&body), "AMZ");
    }

    #[test]
    fn bool_true_escreve_o_nome_da_chave_e_false_nada() {
        assert_eq!(canonical(&json!({"push": true})), "push");
        assert_eq!(canonical(&json!({"push": false})), "");
        assert_eq!(canonical(&json!({"push": null})), "");
    }

    #[test]
    fn string_vazia_e_chave_ausente_dao_o_mesmo_resultado() {
        // É o que permite mandar "pin":"" por paridade com o app oficial sem
        // mudar a assinatura. Os dois payloads assinam igual.
        let com_vazio = json!({"a": "1", "pin": "", "b": "2"});
        let sem_chave = json!({"a": "1", "b": "2"});
        assert_eq!(canonical(&com_vazio), canonical(&sem_chave));
        assert_eq!(canonical(&com_vazio), "12");
    }

    #[test]
    fn numero_sai_como_numero() {
        // O `id` do hashArray vai como inteiro 0 (índice), não como string.
        assert_eq!(canonical(&json!({"id": 0})), "0");
        assert_eq!(canonical(&json!({"id": 42})), "42");
    }

    #[test]
    fn array_e_objeto_recorrem() {
        // Dentro do elemento, `hash` vem antes de `id` (ordem alfabética).
        let body = json!({"hashArray": [{"id": 1, "hash": "H"}]});
        assert_eq!(canonical(&body), "H1");
    }

    #[test]
    fn tokensessao_modo_pin_otp() {
        // push:false e nomeAplicacaoDesktop vazio (paridade com o construtor
        // PasswordAndOtpAuthentication do app). Ordem alfabética:
        // desktopCode, issue, nomeAplicacaoDesktop, otp, pin, push, serialNumber
        let body = json!({
            "desktopCode": "DC", "pin": "1234", "otp": "999999",
            "push": false, "nomeAplicacaoDesktop": "",
            "issue": "CN=AC", "serialNumber": "SN",
        });
        assert_eq!(canonical(&body), "DCCN=AC9999991234SN");
    }

    #[test]
    fn tokensessao_modo_push_inclui_a_palavra_push() {
        // No caminho push o app manda pin e otp VAZIOS e push=true; o bool
        // passa a contribuir com o nome da chave, na posição alfabética dele.
        let body = json!({
            "desktopCode": "DC", "pin": "", "otp": "",
            "push": true, "nomeAplicacaoDesktop": "RemoteID-linux",
            "issue": "CN=AC", "serialNumber": "SN",
        });
        assert_eq!(canonical(&body), "DCCN=ACRemoteID-linuxpushSN");
    }

    #[test]
    fn request_hash_tem_a_forma_da_run_que_o_servidor_aceitou() {
        // Mesma FORMA do corpo aceito na run de 02/09/2026 (valores trocados
        // por sintéticos: os reais identificam o titular do certificado).
        // Ordem: algorithm, desktopCode, hashArray, issue, serialNumber, sessionToken
        let body = json!({
            "desktopCode": "DC",
            "sessionToken": "ST",
            "issue": "CN=AC",
            "serialNumber": "SN",
            "algorithm": "SHA256",
            "hashArray": [{"id": 0, "hash": "SGFzaA=="}],
        });
        assert_eq!(canonical(&body), "SHA256DCSGFzaA==0CN=ACSNST");
    }
}
