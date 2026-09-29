//! A cadeia de autoridades do certificado da carteira (núcleo puro).
//!
//! A carteira do RemoteID entrega só o certificado final. Um token físico
//! costuma guardar a cadeia inteira, e há assinador que depende disso: o do
//! Projudi (TJPR) pede `KeyStore.getCertificateChain` ao SunPKCS11, e com uma
//! cadeia de tamanho 1 cai num caminho de "completar a cadeia" que está
//! quebrado do lado dele (issue 22). A assinatura sai sem as intermediárias e o
//! servidor do tribunal não chega a uma raiz.
//!
//! As autoridades vêm do próprio certificado: a extensão Authority Information
//! Access aponta, em `caIssuers`, para um pacote `.p7c` com o emissor (e, na
//! ICP-Brasil, a cadeia inteira até a raiz). Este crate faz as três partes que
//! não precisam de rede:
//!
//! - [`url_ca_issuers`]: de onde baixar;
//! - [`certificados_do_pacote`]: o que veio no download;
//! - [`montar`]: a ordem, do emissor do final até a raiz.
//!
//! O download é da borda (a porta `FonteDeCadeia`), e o laço que junta tudo é
//! do motor.
//!
//! # Por que casar por nome E por identificador de chave
//!
//! O SunPKCS11 monta a cadeia procurando no token o certificado cujo
//! `CKA_SUBJECT` é o emissor do anterior. Só o nome não basta para escolher
//! entre dois candidatos: uma AC renovada com chave nova mantém o nome, e um
//! pacote pode trazer as duas. Quando o filho traz o Authority Key Identifier
//! e o candidato o Subject Key Identifier, os dois têm de bater; quando falta
//! um deles, vale só o nome.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, SubjectKeyIdentifier,
};
use x509_cert::Certificate;

use remoteid_tipos::{Error, Result};

// OIDs literais, como no `remoteid-assinatura`: são poucos, não mudam, e dá
// para conferir cada um contra a RFC sem sair do arquivo.
/// id-signedData, RFC 5652 §5.1
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-pe-authorityInfoAccess, RFC 5280 §4.2.2.1
const OID_AIA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
/// id-ad-caIssuers, RFC 5280 §4.2.2.1
const OID_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");
/// id-ce-subjectKeyIdentifier, RFC 5280 §4.2.1.2
const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// id-ce-authorityKeyIdentifier, RFC 5280 §4.2.1.1
const OID_AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// As autoridades acima do certificado final, em DER, na ordem da cadeia: o
/// emissor do final primeiro, a raiz (se veio) por último.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cadeia {
    pub autoridades: Vec<Vec<u8>>,
    /// Verdade quando a última autoridade é autoassinada, isto é, a cadeia
    /// chegou à raiz. Uma cadeia incompleta ainda serve: o que o validador do
    /// outro lado não tem são as intermediárias, a raiz ele já conhece.
    pub completa: bool,
}

/// A URL de `caIssuers` do AIA do certificado, se houver uma que dê para
/// baixar por HTTP.
///
/// `ldap://` é ignorada: a borda só fala HTTP, e a ICP-Brasil publica as
/// duas formas. Entre várias HTTP, vale a primeira, que é a ordem em que a AC
/// as declarou.
pub fn url_ca_issuers(der: &[u8]) -> Result<Option<String>> {
    let cert = decodificar(der)?;
    let Some(ext) = extensao(&cert, OID_AIA) else {
        return Ok(None);
    };
    let aia = AuthorityInfoAccessSyntax::from_der(ext)
        .map_err(|e| Error::cripto(format!("extensão AIA ilegível: {e}")))?;
    Ok(aia
        .0
        .iter()
        .filter(|d| d.access_method == OID_CA_ISSUERS)
        .filter_map(|d| match &d.access_location {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        })
        .find(|uri| {
            let minusculo = uri.to_ascii_lowercase();
            minusculo.starts_with("http://") || minusculo.starts_with("https://")
        })
        .map(str::to_string))
}

/// Os certificados, em DER, de um pacote baixado do `caIssuers`.
///
/// Aceita as duas formas que a RFC 5280 §4.2.2.1 prevê para o `caIssuers`
/// por HTTP: um `.p7c` (SignedData "certs-only", DER) ou um único certificado
/// X.509 em DER (`.cer`). Qualquer outra coisa é erro: um pacote que não se
/// deixa ler não pode virar uma cadeia vazia calada.
pub fn certificados_do_pacote(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if let Ok(info) = ContentInfo::from_der(bytes) {
        if info.content_type != OID_SIGNED_DATA {
            return Err(Error::cripto(format!(
                "pacote do caIssuers é CMS de tipo {}, esperado signedData",
                info.content_type
            )));
        }
        let sd: SignedData = info
            .content
            .decode_as()
            .map_err(|e| Error::cripto(format!("SignedData do pacote ilegível: {e}")))?;
        let mut certs = Vec::new();
        for escolha in sd.certificates.iter().flat_map(|c| c.0.iter()) {
            if let CertificateChoices::Certificate(c) = escolha {
                certs.push(
                    c.to_der()
                        .map_err(|e| Error::cripto(format!("certificado do pacote: {e}")))?,
                );
            }
        }
        return Ok(certs);
    }
    // Não é CMS: o `caIssuers` também pode servir um certificado solto.
    decodificar(bytes)
        .map(|_| vec![bytes.to_vec()])
        .map_err(|_| Error::cripto("pacote do caIssuers não é PKCS#7 nem X.509 em DER"))
}

/// A cadeia do certificado `final_der`, montada com o que houver em
/// `candidatos` (a ordem deles não importa, e sobra pode vir).
///
/// Para quando chega a uma autoassinada ([`Cadeia::completa`]) ou quando o
/// próximo emissor não está entre os candidatos. Um candidato nunca entra duas
/// vezes, então um pacote com um laço de certificação cruzada não trava aqui.
/// O próprio certificado final não entra: ele já está no token.
pub fn montar(final_der: &[u8], candidatos: &[Vec<u8>]) -> Result<Cadeia> {
    let mut atual = decodificar(final_der)?;
    // Os candidatos ilegíveis ficam de fora em vez de derrubar a cadeia: o
    // pacote vem de fora, e um intruso não deve apagar o que dá para usar.
    let candidatos: Vec<(&Vec<u8>, Certificate)> = candidatos
        .iter()
        .filter_map(|der| decodificar(der).ok().map(|c| (der, c)))
        .collect();

    let mut cadeia = Cadeia::default();
    if autoassinado(&atual) {
        cadeia.completa = true;
        return Ok(cadeia);
    }
    let mut usados: Vec<&[u8]> = vec![final_der];
    loop {
        let emissor = candidatos
            .iter()
            .find(|(der, c)| !usados.contains(&der.as_slice()) && emitiu(c, &atual));
        let Some((der, cert)) = emissor else {
            return Ok(cadeia);
        };
        usados.push(der);
        cadeia.autoridades.push((*der).clone());
        if autoassinado(cert) {
            cadeia.completa = true;
            return Ok(cadeia);
        }
        atual = cert.clone();
    }
}

/// O certificado cuja URL de `caIssuers` leva ao próximo pedaço da cadeia: a
/// última autoridade já encontrada, ou o próprio final se nenhuma foi.
///
/// É o passo do laço de download do motor quando um pacote não traz a cadeia
/// inteira (algumas ACs publicam só o próprio certificado).
pub fn proximo_a_seguir<'a>(final_der: &'a [u8], cadeia: &'a Cadeia) -> &'a [u8] {
    cadeia
        .autoridades
        .last()
        .map(Vec::as_slice)
        .unwrap_or(final_der)
}

fn decodificar(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|e| Error::cripto(format!("X.509 inválido: {e}")))
}

/// O conteúdo (o `extnValue`) da extensão `oid`, se o certificado a tiver.
fn extensao(cert: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

fn autoassinado(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

/// `pai` emitiu `filho`: o nome bate e, quando os dois lados declaram, o
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

    // A cadeia SINTÉTICA do mock: final → AC TESTE DESKTOPID → AC RAIZ TESTE
    // DESKTOPID. Nenhum certificado real entra em teste versionado.
    const FINAL: &[u8] = include_bytes!("../../remoteid-mock/fixtures/fake-cert.der");
    const PACOTE: &[u8] = include_bytes!("../../remoteid-mock/fixtures/AC_TESTE_DESKTOPID.p7c");

    fn ac_e_raiz() -> (Vec<u8>, Vec<u8>) {
        let certs = certificados_do_pacote(PACOTE).unwrap();
        let ac = certs
            .iter()
            .find(|c| !autoassinado(&decodificar(c).unwrap()))
            .unwrap()
            .clone();
        let raiz = certs
            .iter()
            .find(|c| autoassinado(&decodificar(c).unwrap()))
            .unwrap()
            .clone();
        (ac, raiz)
    }

    #[test]
    fn a_url_do_ca_issuers_sai_do_aia() {
        assert_eq!(
            url_ca_issuers(FINAL).unwrap().as_deref(),
            Some("http://localhost:8799/repositorio/AC_TESTE_DESKTOPID.p7c")
        );
    }

    #[test]
    fn certificado_sem_aia_nao_tem_url() {
        let (_, raiz) = ac_e_raiz();
        assert_eq!(url_ca_issuers(&raiz).unwrap(), None);
    }

    #[test]
    fn o_p7c_traz_os_dois_certificados() {
        assert_eq!(certificados_do_pacote(PACOTE).unwrap().len(), 2);
    }

    #[test]
    fn um_certificado_solto_tambem_e_pacote() {
        assert_eq!(certificados_do_pacote(FINAL).unwrap(), vec![FINAL.to_vec()]);
    }

    #[test]
    fn pacote_ilegivel_e_erro_e_nao_cadeia_vazia() {
        assert!(certificados_do_pacote(b"<html>404</html>").is_err());
        assert!(certificados_do_pacote(&[]).is_err());
    }

    #[test]
    fn a_cadeia_vai_do_emissor_ate_a_raiz() {
        let (ac, raiz) = ac_e_raiz();
        let cadeia = montar(FINAL, &certificados_do_pacote(PACOTE).unwrap()).unwrap();
        assert_eq!(cadeia.autoridades, vec![ac, raiz]);
        assert!(cadeia.completa);
    }

    #[test]
    fn a_ordem_dos_candidatos_e_a_sobra_nao_importam() {
        let (ac, raiz) = ac_e_raiz();
        // Raiz primeiro, repetida, e o próprio final no meio: nada disso pode
        // mudar a cadeia nem fazer o final entrar como autoridade.
        let candidatos = vec![raiz.clone(), FINAL.to_vec(), raiz.clone(), ac.clone()];
        let cadeia = montar(FINAL, &candidatos).unwrap();
        assert_eq!(cadeia.autoridades, vec![ac, raiz]);
        assert!(cadeia.completa);
    }

    #[test]
    fn sem_a_intermediaria_a_raiz_nao_entra() {
        // A raiz não emitiu o final: pular um elo daria uma cadeia que não
        // fecha, pior que nenhuma.
        let (_, raiz) = ac_e_raiz();
        let cadeia = montar(FINAL, &[raiz]).unwrap();
        assert!(cadeia.autoridades.is_empty());
        assert!(!cadeia.completa);
    }

    #[test]
    fn so_a_intermediaria_da_uma_cadeia_incompleta_e_o_proximo_passo_e_ela() {
        let (ac, _) = ac_e_raiz();
        let cadeia = montar(FINAL, std::slice::from_ref(&ac)).unwrap();
        assert_eq!(cadeia.autoridades, vec![ac.clone()]);
        assert!(!cadeia.completa);
        assert_eq!(proximo_a_seguir(FINAL, &cadeia), ac.as_slice());
    }

    #[test]
    fn sem_nada_o_proximo_passo_e_o_proprio_final() {
        let cadeia = montar(FINAL, &[]).unwrap();
        assert_eq!(proximo_a_seguir(FINAL, &cadeia), FINAL);
    }

    #[test]
    fn um_final_autoassinado_ja_esta_completo() {
        let (_, raiz) = ac_e_raiz();
        let cadeia = montar(&raiz, &certificados_do_pacote(PACOTE).unwrap()).unwrap();
        assert!(cadeia.autoridades.is_empty());
        assert!(cadeia.completa);
    }

    #[test]
    fn candidato_ilegivel_fica_de_fora_sem_derrubar_a_cadeia() {
        let (ac, raiz) = ac_e_raiz();
        let candidatos = vec![b"lixo".to_vec(), ac.clone(), raiz.clone()];
        assert_eq!(
            montar(FINAL, &candidatos).unwrap().autoridades,
            vec![ac, raiz]
        );
    }

    #[test]
    fn mesmo_nome_com_outra_chave_nao_e_o_emissor() {
        // A AC "renovada": o subject é o mesmo, a chave não. O AKI do final
        // aponta para a chave antiga, então a renovada não pode entrar.
        let (ac, _) = ac_e_raiz();
        let mut renovada = decodificar(&ac).unwrap();
        let exts = renovada.tbs_certificate.extensions.as_mut().unwrap();
        let ski = exts.iter_mut().find(|e| e.extn_id == OID_SKI).unwrap();
        ski.extn_value = der::asn1::OctetString::new(
            SubjectKeyIdentifier(der::asn1::OctetString::new(vec![0x42; 20]).unwrap())
                .to_der()
                .unwrap(),
        )
        .unwrap();
        let renovada = renovada.to_der().unwrap();
        let cadeia = montar(FINAL, &[renovada]).unwrap();
        assert!(cadeia.autoridades.is_empty());
    }
}
