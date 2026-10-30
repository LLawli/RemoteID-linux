//! A cadeia de autoridades do certificado da carteira, sem rede.
//!
//! A carteira do RemoteID entrega só o certificado final, e há assinador que
//! precisa da cadeia no token: o do Projudi (TJPR) pede
//! `KeyStore.getCertificateChain` ao SunPKCS11, e com uma cadeia de tamanho 1
//! a assinatura sai sem as intermediárias e o tribunal não chega a uma raiz
//! (issue 22 do RemoteID-linux).
//!
//! As autoridades vêm do próprio certificado: o `caIssuers` do Authority
//! Information Access aponta para um `.p7c` com o emissor (na ICP-Brasil, a
//! cadeia inteira até a raiz). Aqui ficam as partes puras; o download é do
//! motor.
//!
//! O emissor é casado pelo nome e, quando os dois lados declaram, pelo
//! identificador de chave: uma AC renovada com chave nova mantém o nome, e um
//! pacote pode trazer as duas.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, SubjectKeyIdentifier,
};

/// id-signedData, RFC 5652 §5.1.
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-pe-authorityInfoAccess, RFC 5280 §4.2.2.1.
const OID_AIA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
/// id-ad-caIssuers, RFC 5280 §4.2.2.1.
const OID_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");
/// id-ce-subjectKeyIdentifier, RFC 5280 §4.2.1.2.
const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// id-ce-authorityKeyIdentifier, RFC 5280 §4.2.1.1.
const OID_AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// As autoridades acima do certificado final, em DER, do emissor dele até a
/// raiz.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cadeia {
    pub autoridades: Vec<Vec<u8>>,
    /// A última autoridade é autoassinada. Uma cadeia incompleta ainda serve:
    /// ao validador faltam as intermediárias, a raiz ele já conhece.
    pub completa: bool,
}

/// A primeira URL HTTP do `caIssuers`. A de LDAP fica de fora: a ICP-Brasil
/// publica as duas.
pub fn url_ca_issuers(der: &[u8]) -> Result<Option<String>, String> {
    let certificado = decodificar(der)?;
    let Some(extensao) = extensao(&certificado, OID_AIA) else {
        return Ok(None);
    };
    let aia = AuthorityInfoAccessSyntax::from_der(extensao)
        .map_err(|e| format!("extensão AIA ilegível: {e}"))?;
    Ok(aia
        .0
        .iter()
        .filter(|d| d.access_method == OID_CA_ISSUERS)
        .filter_map(|d| match &d.access_location {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        })
        .find(|uri| {
            let uri = uri.to_ascii_lowercase();
            uri.starts_with("http://") || uri.starts_with("https://")
        })
        .map(str::to_string))
}

/// Os certificados de um pacote do `caIssuers`: um `.p7c` (SignedData só com
/// certificados) ou um `.cer` solto, as duas formas da RFC 5280. Outra coisa é
/// erro, e não uma cadeia vazia calada.
pub fn certificados_do_pacote(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let Ok(info) = ContentInfo::from_der(bytes) else {
        return decodificar(bytes)
            .map(|_| vec![bytes.to_vec()])
            .map_err(|_| "o pacote do caIssuers não é PKCS#7 nem X.509 em DER".into());
    };
    if info.content_type != OID_SIGNED_DATA {
        return Err(format!(
            "o pacote do caIssuers é CMS do tipo {}, e não signedData",
            info.content_type
        ));
    }
    let assinados: SignedData = info
        .content
        .decode_as()
        .map_err(|e| format!("SignedData do pacote ilegível: {e}"))?;
    assinados
        .certificates
        .iter()
        .flat_map(|c| c.0.iter())
        .filter_map(|escolha| match escolha {
            CertificateChoices::Certificate(c) => Some(c),
            _ => None,
        })
        .map(|c| {
            c.to_der()
                .map_err(|e| format!("certificado do pacote: {e}"))
        })
        .collect()
}

/// A cadeia de `final_der` com o que houver em `candidatos`, em qualquer
/// ordem e com sobra. Para na autoassinada ou quando o próximo emissor não
/// está entre eles; um candidato nunca entra duas vezes, então certificação
/// cruzada não vira laço. O final não entra: ele já está no token.
pub fn montar(final_der: &[u8], candidatos: &[Vec<u8>]) -> Result<Cadeia, String> {
    let mut atual = decodificar(final_der)?;
    // Um candidato ilegível fica de fora: o pacote vem de fora, e um intruso
    // não apaga o que dá para usar.
    let candidatos: Vec<(&[u8], Certificate)> = candidatos
        .iter()
        .filter_map(|der| Some((der.as_slice(), decodificar(der).ok()?)))
        .collect();
    let mut cadeia = Cadeia {
        completa: autoassinado(&atual),
        ..Cadeia::default()
    };
    let mut usados = vec![final_der];
    while !cadeia.completa {
        let Some((der, emissor)) = candidatos
            .iter()
            .find(|(der, c)| !usados.contains(der) && emitiu(c, &atual))
        else {
            break;
        };
        usados.push(der);
        cadeia.autoridades.push(der.to_vec());
        cadeia.completa = autoassinado(emissor);
        atual = emissor.clone();
    }
    Ok(cadeia)
}

/// O certificado cujo `caIssuers` leva ao próximo pedaço: a última autoridade
/// achada, ou o final. É o passo seguinte quando a AC publica só o próprio
/// certificado, e não a cadeia inteira.
pub fn proximo_a_seguir<'a>(final_der: &'a [u8], cadeia: &'a Cadeia) -> &'a [u8] {
    cadeia.autoridades.last().map_or(final_der, Vec::as_slice)
}

fn decodificar(der: &[u8]) -> Result<Certificate, String> {
    Certificate::from_der(der).map_err(|e| format!("X.509 inválido: {e}"))
}

fn extensao(certificado: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    certificado
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

fn autoassinado(certificado: &Certificate) -> bool {
    certificado.tbs_certificate.subject == certificado.tbs_certificate.issuer
}

/// `pai` emitiu `filho`: o nome bate e, quando os dois declaram, o
/// identificador de chave também.
fn emitiu(pai: &Certificate, filho: &Certificate) -> bool {
    if pai.tbs_certificate.subject != filho.tbs_certificate.issuer {
        return false;
    }
    let aki = extensao(filho, OID_AKI)
        .and_then(|b| AuthorityKeyIdentifier::from_der(b).ok())
        .and_then(|a| a.key_identifier);
    let ski = extensao(pai, OID_SKI).and_then(|b| SubjectKeyIdentifier::from_der(b).ok());
    match (aki, ski) {
        (Some(aki), Some(ski)) => aki == ski.0,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A cadeia sintética do servidor falso: final, AC TESTE DESKTOPID e AC
    // RAIZ TESTE DESKTOPID.
    const FINAL: &[u8] = include_bytes!("../tests/mock/fake-cert.der");
    const PACOTE: &[u8] = include_bytes!("../tests/mock/AC_TESTE_DESKTOPID.p7c");

    fn ac_e_raiz() -> (Vec<u8>, Vec<u8>) {
        let certificados = certificados_do_pacote(PACOTE).unwrap();
        let (raiz, ac): (Vec<_>, Vec<_>) = certificados
            .into_iter()
            .partition(|c| autoassinado(&decodificar(c).unwrap()));
        (ac[0].clone(), raiz[0].clone())
    }

    #[test]
    fn a_url_sai_do_aia_e_a_raiz_nao_tem() {
        assert_eq!(
            url_ca_issuers(FINAL).unwrap().as_deref(),
            Some("http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c")
        );
        assert_eq!(url_ca_issuers(&ac_e_raiz().1).unwrap(), None);
    }

    #[test]
    fn le_o_p7c_e_o_certificado_solto_e_recusa_o_resto() {
        assert_eq!(certificados_do_pacote(PACOTE).unwrap().len(), 2);
        assert_eq!(certificados_do_pacote(FINAL).unwrap(), [FINAL]);
        assert!(certificados_do_pacote(b"<html>404</html>").is_err());
        assert!(certificados_do_pacote(&[]).is_err());
    }

    #[test]
    fn a_cadeia_vai_do_emissor_ate_a_raiz_em_qualquer_ordem() {
        let (ac, raiz) = ac_e_raiz();
        let esperada = Cadeia {
            autoridades: vec![ac.clone(), raiz.clone()],
            completa: true,
        };
        assert_eq!(
            montar(FINAL, &[ac.clone(), raiz.clone()]).unwrap(),
            esperada
        );
        assert_eq!(
            montar(FINAL, &[raiz.clone(), b"lixo".to_vec(), ac.clone()]).unwrap(),
            esperada
        );
    }

    #[test]
    fn sem_a_raiz_a_cadeia_fica_incompleta_e_sem_o_emissor_vazia() {
        let (ac, raiz) = ac_e_raiz();
        let so_ac = montar(FINAL, std::slice::from_ref(&ac)).unwrap();
        assert_eq!(so_ac.autoridades, std::slice::from_ref(&ac));
        assert!(!so_ac.completa);
        assert_eq!(proximo_a_seguir(FINAL, &so_ac), ac.as_slice());
        let nada = montar(FINAL, &[raiz]).unwrap();
        assert_eq!(nada, Cadeia::default());
        assert_eq!(proximo_a_seguir(FINAL, &nada), FINAL);
    }

    #[test]
    fn a_raiz_sozinha_ja_e_completa() {
        let (_, raiz) = ac_e_raiz();
        assert_eq!(
            montar(&raiz, &[]).unwrap(),
            Cadeia {
                autoridades: vec![],
                completa: true
            }
        );
    }
}
