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
//! - **Sempre mascarados, sem exceção** ([`DADOS_PESSOAIS`]): o que identifica
//!   o titular (nome, CPF, RG, e-mail, data de nascimento e o resto que o
//!   servidor ecoa em `certificate`). Seguem a regra dos segredos, e não a das
//!   credenciais, porque o modo cru existe para depurar token, não para ler o
//!   RG de ninguém.
//! - **Sempre impressão digital** ([`IDENTIFICADORES`]): o serial do
//!   certificado (em qualquer das grafias do protocolo), a `cert_key` que o
//!   carrega e a assinatura devolvida. O hash basta para responder "é o mesmo
//!   certificado da linha de cima?", e o tamanho basta para a assinatura.
//! - `cru = true` (o `REMOTEID_DIAG_RAW=1`) desliga só a máscara dos tokens; os
//!   outros grupos continuam mascarados mesmo assim.
//!
//! Ficam em claro, de propósito, `emissor`, `issue`, `validoDe` e `validoAte`:
//! é com eles que se diagnostica certificado vencido ou de outra AC.

use serde_json::{json, Map, Value};

use remoteid_cripto::sha256;

/// Campos cujo valor nunca é gravado, nem no modo cru.
pub const SEGREDOS: &[&str] = &["senha", "password", "passwd", "pwd", "pin", "otp"];

/// Campos gravados como impressão digital, a menos que `cru`.
pub const CREDENCIAIS: &[&str] = &["token", "sessiontoken", "authorization", "chaveprivada"];

/// Dados do titular: nunca gravados, nem no modo cru.
///
/// São os que a resposta de `requestHashSessionSignature` ecoa em
/// `certificate` a cada assinatura, mais o `email`/`cpf` que o `tokensessao` e
/// o login também devolvem. O relato LLawli/adv-br-relatos#15 chegou com nome,
/// RG e data de nascimento de quem o enviou antes deste grupo existir.
pub const DADOS_PESSOAIS: &[&str] = &[
    "titular",
    "rg",
    "datanascimento",
    "cpf",
    "email",
    "orgaoexpedidor",
    "ufexpedidor",
    "tituloeleitor",
    "pispasep",
    "cei",
    "upn",
    "municipioeleitoral",
    "zonaeleitoral",
    "secaoeleitoral",
    "responsavelcnpj",
    "nomeempresarial",
    // A resposta do `tokensessao` traz um `tokenOTP` ao lado do `pin`. O que
    // ele carrega não foi caracterizado; pelo nome, é do OTP, e mascarar a
    // mais não custa nada ao diagnóstico.
    "tokenotp",
];

/// Campos gravados sempre como impressão digital, mesmo no modo cru.
///
/// O serial aparece com três nomes: `numeroSerie` em `certificate`,
/// `numeroSerieCertificado` na carteira e no `tokensessao`, `serialNumber` nos
/// pedidos. A `cert_key` é serial mais emissor, e o hash dela é estável do
/// mesmo jeito, então eventos de sessão continuam comparáveis entre si.
pub const IDENTIFICADORES: &[&str] = &[
    "numeroserie",
    "numeroseriecertificado",
    "serialnumber",
    "cert_key",
    "signaturebase64",
];

/// Aplica a política de redação a um valor arbitrário, recursivamente.
pub fn redigir(valor: &Value, cru: bool) -> Value {
    match valor {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let chave = k.to_lowercase();
                let em = |grupo: &[&str]| grupo.contains(&chave.as_str());
                if em(SEGREDOS) || em(DADOS_PESSOAIS) {
                    out.insert(k.clone(), json!(mascara_segredo(v)));
                } else if em(IDENTIFICADORES) || (!cru && em(CREDENCIAIS)) {
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

/// Segredo ou dado pessoal: nem o tamanho é informado.
fn mascara_segredo(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() => "<vazio>".into(),
        Value::Null => "<ausente>".into(),
        _ => "<redigido>".into(),
    }
}

/// Credencial ou identificador: tamanho e hash, o suficiente para comparar duas
/// ocorrências.
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
    fn campos_comuns_ficam_em_claro() {
        // A redação tem de ser cirúrgica: o diag só serve para depurar se
        // `desktopCode`, `issue`, `algorithm` e afins continuarem legíveis.
        // Redigir demais é o outro jeito de o diag ficar inútil.
        let v = json!({"desktopCode": "DC-1", "algorithm": "", "hashArray": [{"id": 0, "hash": "QQ=="}]});
        let saida = redigir(&v, false);
        assert_eq!(saida["desktopCode"], "DC-1");
        assert_eq!(saida["algorithm"], "");
        assert_eq!(saida["hashArray"][0]["hash"], "QQ==");
    }

    #[test]
    fn segredo_preenchido_e_redigido_e_nao_rotulado_como_vazio() {
        let saida = redigir(&json!({"pin": "1234", "senha": "s3cr3t"}), false);
        assert_eq!(saida["pin"], "<redigido>");
        assert_eq!(saida["senha"], "<redigido>");
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

    /// A forma de `body.certificate` na resposta de
    /// `requestHashSessionSignature`, com dados fictícios.
    fn resposta_de_assinatura() -> Value {
        json!({
            "status": true,
            "message": "",
            "certificate": {
                "numeroSerie": "5EC1A1F1C71C10",
                "emissor": "AC FICTICIA G3",
                "validoDe": "2025-01-02T03:04:05",
                "validoAte": "2028-01-02T03:04:05",
                "titular": "FULANA DE TAL FICTICIA",
                "email": "fulana@exemplo.invalid",
                "cpf": "00011122233",
                "rg": "998877665",
                "dataNascimento": "1901-02-03",
                "orgaoExpedidor": "SSPFIC",
                "ufExpedidor": "ZZ",
                "tituloEleitor": "777766665555",
                "pisPasep": "44433322211",
                "cei": "123456789012",
                "upn": "fulana@upn.invalid",
                "municipioEleitoral": "CIDADE FICTICIA",
                "zonaEleitoral": "0042",
                "secaoEleitoral": "0137",
                "responsavelCnpj": "FULANO RESPONSAVEL",
                "nomeEmpresarial": "EMPRESA FICTICIA LTDA"
            },
            "idArray": [
                {"id": "0", "status": true, "message": "", "signatureBase64": "QUJDREVGR0hJSktM"}
            ]
        })
    }

    const VALORES_PESSOAIS: &[&str] = &[
        "FULANA",
        "fulana@exemplo.invalid",
        "00011122233",
        "998877665",
        "1901-02-03",
        "SSPFIC",
        "\"ZZ\"",
        "777766665555",
        "44433322211",
        "123456789012",
        "fulana@upn.invalid",
        "CIDADE FICTICIA",
        "0042",
        "0137",
        "FULANO RESPONSAVEL",
        "EMPRESA FICTICIA",
    ];

    #[test]
    fn dados_pessoais_do_certificado_nunca_aparecem_nem_no_modo_cru() {
        for cru in [false, true] {
            let saida = redigir(&json!({"body": resposta_de_assinatura()}), cru).to_string();
            for valor in VALORES_PESSOAIS {
                assert!(
                    !saida.contains(valor),
                    "vazou {valor} com cru={cru}: {saida}"
                );
            }
            assert!(
                !saida.contains("5EC1A1F1C71C10"),
                "o serial vazou com cru={cru}"
            );
            assert!(
                !saida.contains("QUJDREVGR0hJSktM"),
                "a assinatura vazou com cru={cru}"
            );
        }
    }

    #[test]
    fn dado_pessoal_e_redigido_sem_tamanho() {
        let saida = redigir(&resposta_de_assinatura(), false);
        assert_eq!(saida["certificate"]["titular"], "<redigido>");
        assert_eq!(saida["certificate"]["dataNascimento"], "<redigido>");
    }

    #[test]
    fn o_que_diagnostica_o_certificado_fica_em_claro() {
        // Emissor e validade são o que responde "venceu?" e "é de outra AC?".
        let saida = redigir(&resposta_de_assinatura(), true);
        let cert = &saida["certificate"];
        assert_eq!(cert["emissor"], "AC FICTICIA G3");
        assert_eq!(cert["validoDe"], "2025-01-02T03:04:05");
        assert_eq!(cert["validoAte"], "2028-01-02T03:04:05");
        assert_eq!(saida["idArray"][0]["status"], true);
    }

    #[test]
    fn serial_vira_a_mesma_impressao_digital_em_qualquer_grafia() {
        // O mesmo serial com os três nomes do protocolo tem de dar o mesmo
        // hash, senão o diag não liga o pedido à resposta.
        let v = json!({
            "numeroSerie": "5EC1A1F1C71C10",
            "numeroSerieCertificado": "5EC1A1F1C71C10",
            "serialNumber": "5EC1A1F1C71C10",
        });
        let saida = redigir(&v, true);
        assert!(saida["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("<oculto len=14 sha256="));
        assert_eq!(saida["numeroSerie"], saida["serialNumber"]);
        assert_eq!(saida["numeroSerieCertificado"], saida["serialNumber"]);
    }

    #[test]
    fn cert_key_vira_impressao_digital_estavel() {
        let chave = "5EC1A1F1C71C10;CN=AC FICTICIA G3,O=ICP-Brasil,C=BR";
        let a = redigir(&json!({"cert_key": chave}), false);
        let b = redigir(&json!({"cert_key": chave}), true);
        assert_eq!(a, b, "a mesma cert_key tem de dar o mesmo hash, cru ou não");
        assert!(!a.to_string().contains("5EC1A1F1C71C10"));
    }
}
