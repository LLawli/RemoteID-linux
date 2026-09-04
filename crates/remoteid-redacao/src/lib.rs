//! Redação de segredos para o log de diagnóstico (núcleo puro).
//!
//! O log é feito para ser ENVIADO a terceiros, então a redação é o padrão, não
//! um extra. Esta é a LÓGICA pura (valor entra, valor redigido sai); o sink que
//! grava em arquivo (o adaptador de diagnóstico) só a aplica, então a garantia
//! "PIN/OTP nunca vazam" é testável isoladamente e não depende de o chamador
//! lembrar de redigir.
//!
//! - **Sempre mascarados, sem exceção** ([`SEGREDOS`]): `senha`, `pin`, `otp` e
//!   variantes. Nem o tamanho é informado (o tamanho de um PIN já é dica).
//! - **Mascarados por padrão** ([`CREDENCIAIS`]): tokens e `Authorization`.
//!   Viram uma impressão digital `<oculto len=N sha256=abcdef12>`, que permite
//!   responder "é o mesmo token da linha de cima?" sem revelar o valor.
//! - `cru = true` (o `REMOTEID_DIAG_RAW=1`) desliga só a máscara dos tokens; os
//!   segredos do primeiro grupo continuam mascarados mesmo assim.

use serde_json::{json, Map, Value};

use remoteid_cripto::sha256;

/// Campos cujo valor nunca é gravado, nem no modo cru.
pub const SEGREDOS: &[&str] = &["senha", "password", "passwd", "pwd", "pin", "otp"];

/// Campos gravados como impressão digital, a menos que `cru`.
pub const CREDENCIAIS: &[&str] = &["token", "sessiontoken", "authorization", "chaveprivada"];

/// Aplica a política de redação a um valor arbitrário, recursivamente.
pub fn redigir(valor: &Value, cru: bool) -> Value {
    match valor {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let chave = k.to_lowercase();
                if SEGREDOS.iter().any(|s| chave == *s) {
                    out.insert(k.clone(), json!(mascara_segredo(v)));
                } else if !cru && CREDENCIAIS.iter().any(|s| chave == *s) {
                    out.insert(k.clone(), json!(impressao_digital(v)));
                } else {
                    out.insert(k.clone(), redigir(v, cru));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| redigir(v, cru)).collect()),
        outro => outro.clone(),
    }
}

/// Segredo: nem o tamanho é informado.
fn mascara_segredo(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() => "<vazio>".into(),
        Value::Null => "<ausente>".into(),
        _ => "<redigido>".into(),
    }
}

/// Credencial: tamanho e hash, o suficiente para comparar duas ocorrências.
fn impressao_digital(v: &Value) -> String {
    let texto = match v {
        Value::String(s) => s.clone(),
        Value::Null => return "<ausente>".into(),
        outro => outro.to_string(),
    };
    if texto.is_empty() {
        return "<vazio>".into();
    }
    let h = hex(&sha256(texto.as_bytes()));
    format!("<oculto len={} sha256={}>", texto.len(), &h[..8])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_e_otp_nunca_aparecem_nem_no_modo_cru() {
        let corpo = json!({"desktopCode": "DC", "pin": "1234", "otp": "999999", "push": false});
        let saida = redigir(&corpo, true).to_string();
        assert!(!saida.contains("1234"), "o PIN vazou: {saida}");
        assert!(!saida.contains("999999"), "o OTP vazou: {saida}");
        assert!(
            saida.contains("DC"),
            "o que não é segredo tem de continuar legível"
        );
    }

    #[test]
    fn token_vira_impressao_digital_estavel() {
        let a = redigir(&json!({"token": "sessaoAssinatura;327989;..."}), false);
        let b = redigir(&json!({"token": "sessaoAssinatura;327989;..."}), false);
        let c = redigir(&json!({"token": "outro"}), false);
        assert_eq!(a, b, "o mesmo token tem de dar a mesma impressão digital");
        assert_ne!(a, c, "tokens diferentes têm de se distinguir");
        assert!(!a.to_string().contains("327989"));
        assert!(a.to_string().contains("sha256="));
    }

    #[test]
    fn token_no_modo_cru_aparece() {
        // O modo cru (REMOTEID_DIAG_RAW=1) libera só os tokens, para depuração.
        let saida = redigir(&json!({"token": "abc"}), true).to_string();
        assert!(saida.contains("abc"));
    }

    #[test]
    fn redige_dentro_de_estruturas_aninhadas() {
        let v = json!({"request": {"body": {"senha": "s3cr3t"}}});
        assert!(!redigir(&v, false).to_string().contains("s3cr3t"));
    }

    #[test]
    fn distingue_campo_vazio_de_ausente() {
        assert!(redigir(&json!({"otp": ""}), false)
            .to_string()
            .contains("<vazio>"));
        assert!(redigir(&json!({"otp": null}), false)
            .to_string()
            .contains("<ausente>"));
    }
}
