//! Montagem dos payloads, separada da rede para poder ser testada sozinha.
//!
//! Cada função aqui é pura: recebe os dados e devolve o JSON exato que vai no
//! corpo. É onde mora a paridade com o app oficial, então as decisões estão
//! comentadas com a evidência que as sustenta.
//!
//! # Ordem das chaves no JSON
//!
//! Não importa, e é bom deixar isso registrado. O app oficial monta o corpo num
//! `Json::Value` do jsoncpp, que é um `std::map`: a serialização sai em ordem
//! alfabética de chave, independentemente da ordem em que os campos foram
//! inseridos. O `serde_json` sem a feature `preserve_order` usa `BTreeMap` e
//! produz a mesma ordem. De todo modo a ASSINATURA cobre a canônica
//! ([`crate::canonical`]), que ordena por conta própria, então a ordem no fio é
//! cosmética.

use serde_json::{json, Value};

use remoteid_autorizacao::Fatores;
use remoteid_estado::Certificado;

use crate::algoritmo::Algoritmo;

/// `POST /api/manager/usuarios/login/usrsenha`
///
/// A chave é `email`, não `usuario` nem `login`.
pub fn login(email: &str, senha: &str) -> Value {
    json!({ "email": email, "senha": senha })
}

/// `POST /api/manager/desktopid/usuario/{userId}/organizacao/{orgId}`
///
/// `chave_publica` tem de ser o **PEM completo**, com as linhas BEGIN/END.
/// Base64 do DER cru é recusado com ConstraintViolation. E `dominio_rede` não
/// pode ser vazio (o servidor responde `DomainNameLeftBlank`).
pub fn registrar_desktop(
    nome_desktop: &str,
    usuario_local: &str,
    dominio_rede: &str,
    chave_publica_pem: &str,
) -> Value {
    json!({
        "nomeDesktop": nome_desktop,
        "sistemaOperacional": "Linux",
        "nomeUsuarioLocal": usuario_local,
        "dominioRede": dominio_rede,
        "chavePublica": chave_publica_pem,
    })
}

/// Corpo de `carteira` e `statusCelular`: só o instante, como string.
///
/// É o anti-replay: a assinatura do Bearer cobre o corpo, e o corpo tem o
/// momento. Corpo vazio dá 400.
pub fn momento(agora_epoch: u64) -> Value {
    json!({ "momento": agora_epoch.to_string() })
}

/// `POST /api/signature/tokensessao`
///
/// Os sete campos vão SEMPRE, mesmo vazios: `openSession` (`FUN_1000763a2`)
/// insere os sete incondicionalmente, sem nenhum `if`. Como na canônica string
/// vazia e chave ausente dão o mesmo resultado, mandar os campos vazios dá
/// paridade de JSON com o app oficial sem alterar a assinatura.
///
/// A diferença entre os dois caminhos está só nos VALORES, e ela reproduz os
/// dois construtores do app (ver [`crate::authmode`]):
///
/// - pin+otp (estado 2): `pin` e `otp` preenchidos, `push:false`.
/// - push (estado 1): `pin` e `otp` vazios, `push:true`.
///
/// `nome_aplicacao` é o ponto em que este cliente se afasta do app oficial de
/// propósito, e só no caminho pin+otp: o construtor `FUN_100058b9e` deixa o
/// campo vazio, mas a run ao vivo de 02/09/2026 provou que o servidor aceita um
/// valor ali sem reclamar, e um nome identificável ajuda o titular a reconhecer
/// a sessão. No caminho push, que nenhum testador exercitou, seguimos o app à
/// risca e preenchemos o campo (é o construtor push que o preenche, e é o texto
/// que o celular tende a exibir na notificação).
pub fn tokensessao(
    codigo_desktop: &str,
    cert: &Certificado,
    fatores: &Fatores,
    nome_aplicacao: &str,
) -> Value {
    let (pin, otp, push) = match fatores {
        Fatores::PinOtp { pin, otp } => (pin.as_str(), otp.as_str(), false),
        Fatores::Push => ("", "", true),
    };
    json!({
        "desktopCode": codigo_desktop,
        "pin": pin,
        "otp": otp,
        "push": push,
        "nomeAplicacaoDesktop": nome_aplicacao,
        "issue": cert.issue,
        "serialNumber": cert.serial_number,
    })
}

/// `POST /api/signature/requestHashSessionSignature`
///
/// `id` é o ÍNDICE do hash, inteiro. A resposta devolve o mesmo id como
/// **string**: assimetria do backend, não erro do cliente. O `hash` é o base64
/// do digest binário, não do hexadecimal.
///
/// `algorithm` vai SEMPRE, inclusive como string vazia no modo cru
/// ([`Algoritmo::Cru`]): foi com o campo presente e vazio que a sondagem provou
/// o modo, e omitir não foi testado. Na canônica a string vazia não contribui,
/// então a assinatura do Bearer não muda por isso.
pub fn request_hash(
    codigo_desktop: &str,
    session_token: &str,
    cert: &Certificado,
    algoritmo: Algoritmo,
    hashes_b64: &[String],
) -> Value {
    let hash_array: Vec<Value> = hashes_b64
        .iter()
        .enumerate()
        .map(|(i, h)| json!({ "id": i, "hash": h }))
        .collect();
    json!({
        "desktopCode": codigo_desktop,
        "sessionToken": session_token,
        "issue": cert.issue,
        "serialNumber": cert.serial_number,
        "algorithm": algoritmo.nome(),
        "hashArray": hash_array,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical;

    fn cert() -> Certificado {
        Certificado::do_key_name("SN;CN=AC OAB G3", None).unwrap()
    }

    #[test]
    fn tokensessao_manda_os_sete_campos_sempre() {
        let p = tokensessao("DC", &cert(), &Fatores::Push, "RemoteID-linux");
        for chave in [
            "desktopCode",
            "pin",
            "otp",
            "push",
            "nomeAplicacaoDesktop",
            "issue",
            "serialNumber",
        ] {
            assert!(p.get(chave).is_some(), "faltou {chave} no payload");
        }
    }

    #[test]
    fn caminho_push_deixa_pin_e_otp_vazios() {
        // Paridade com FUN_100058de6: o construtor do push não toca em pin/otp.
        let p = tokensessao("DC", &cert(), &Fatores::Push, "RemoteID-linux");
        assert_eq!(p["pin"], "");
        assert_eq!(p["otp"], "");
        assert_eq!(p["push"], true);
    }

    #[test]
    fn caminho_pin_otp_nao_manda_push_true() {
        let f = Fatores::PinOtp {
            pin: "1234".into(),
            otp: "999999".into(),
        };
        let p = tokensessao("DC", &cert(), &f, "RemoteID-linux");
        assert_eq!(p["pin"], "1234");
        assert_eq!(p["otp"], "999999");
        assert_eq!(p["push"], false);
    }

    #[test]
    fn push_muda_a_canonica_porque_o_bool_true_escreve_a_chave() {
        // Este é o ponto em que uma implementação desatenta quebra: trocar o
        // fator sem recalcular a assinatura manda um Bearer que não cobre o
        // corpo, e o servidor responde "Código de autorização inválida" —
        // parecendo erro de OTP quando é erro de assinatura.
        let c = cert();
        let push = canonical(&tokensessao("DC", &c, &Fatores::Push, "App"));
        let pin = canonical(&tokensessao(
            "DC",
            &c,
            &Fatores::PinOtp {
                pin: "1234".into(),
                otp: "999999".into(),
            },
            "App",
        ));
        assert!(
            push.contains("push"),
            "o bool true tem de escrever o nome da chave"
        );
        assert!(!pin.contains("push"), "push:false não pode contribuir");
        assert_ne!(push, pin);
    }

    #[test]
    fn request_hash_usa_id_inteiro_e_indice_crescente() {
        let hashes = vec!["QQ==".to_string(), "Ug==".to_string()];
        let p = request_hash("DC", "ST", &cert(), Algoritmo::Sha256, &hashes);
        assert_eq!(p["hashArray"][0]["id"], 0);
        assert_eq!(p["hashArray"][1]["id"], 1);
        assert!(
            p["hashArray"][0]["id"].is_i64(),
            "id vai como inteiro, não string"
        );
        assert_eq!(p["algorithm"], "SHA256");
    }

    #[test]
    fn modo_cru_manda_algorithm_presente_e_vazio() {
        // Ouro: é o corpo do caso 4 da sondagem de 05/09/2026 (o que fez o
        // servidor assinar um DigestInfo(MD5) sem embrulhar). O campo vai
        // como string vazia, não some do JSON.
        let bloco = vec!["MCAwDAYIKoZIhvcNAgUFAAQQ".to_string()];
        let p = request_hash("DC", "ST", &cert(), Algoritmo::Cru, &bloco);
        assert_eq!(p["algorithm"], "");
        assert!(p.get("algorithm").is_some(), "a chave tem de existir");
        assert_eq!(p["hashArray"][0]["hash"], "MCAwDAYIKoZIhvcNAgUFAAQQ");
        assert_eq!(p["hashArray"][0]["id"], 0);
    }

    #[test]
    fn o_modo_so_muda_o_literal_de_algorithm_no_corpo_e_na_canonica() {
        // Os dois modos usam a MESMA sessão e o mesmo Bearer; a única
        // diferença no fio é o valor de `algorithm`. Na canônica a string
        // vazia não contribui, então o corpo cru canonicaliza como se o campo
        // não existisse: quem assinar o Bearer precisa assinar o corpo de
        // verdade (é o que o motor faz), nunca reserializar.
        let h = vec!["QQ==".to_string()];
        let sha = request_hash("DC", "ST", &cert(), Algoritmo::Sha256, &h);
        let cru = request_hash("DC", "ST", &cert(), Algoritmo::Cru, &h);
        let mut sha_sem = sha.clone();
        let mut cru_sem = cru.clone();
        sha_sem.as_object_mut().unwrap().remove("algorithm");
        cru_sem.as_object_mut().unwrap().remove("algorithm");
        assert_eq!(sha_sem, cru_sem, "fora do algorithm, os corpos são iguais");
        assert!(canonical(&sha).contains("SHA256"));
        assert!(!canonical(&cru).contains("SHA256"));
        assert_eq!(canonical(&cru), canonical(&cru_sem));
    }

    #[test]
    fn momento_vai_como_string_de_segundos() {
        let p = momento(1_788_393_921);
        assert_eq!(p["momento"], "1788393921");
        assert_eq!(canonical(&p), "1788393921");
    }

    #[test]
    fn registro_manda_pem_completo_e_dominio_preenchido() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let p = registrar_desktop("meu-pc", "law", "biglinux", pem);
        assert!(p["chavePublica"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(p["sistemaOperacional"], "Linux");
        assert!(!p["dominioRede"].as_str().unwrap().is_empty());
    }
}
