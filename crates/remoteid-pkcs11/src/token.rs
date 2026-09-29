//! O token: o que este módulo mostra ao mundo, montado a partir do estado local.
//!
//! O `state.json` já tem tudo o que a fatia offline precisa: o certificado X.509
//! do titular em DER. A chave privada NÃO está aqui e nunca estará — ela mora no
//! HSM da Certisign, e é por isso que este módulo existe (ver
//! [[remoteid-pkcs7-e-o-caminho-do-papers]]).

use base64::Engine as _;
use der::{Decode as _, Encode as _};
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;

use cryptoki_sys::*;

use crate::objetos::{Objeto, HANDLE_PRIMEIRA_AUTORIDADE};

use remoteid_cripto::ChaveInstalacao;

/// O único slot que o módulo expõe.
///
/// Fixo, e diferente de zero: há software que trata `0` como "nenhum slot".
pub const ID_SLOT: CK_SLOT_ID = 1;

pub struct Token {
    /// Rótulo do token, que é o que aparece como "dispositivo de segurança" no
    /// Firefox e como nickname na saída do `certutil`.
    pub rotulo: String,
    /// Número de série do certificado, em hexadecimal (vem do `keyName`).
    pub serie: String,
    pub objetos: Vec<Objeto>,
    /// A chave PÚBLICA do certificado, já decodificada do SPKI. Guardada aqui
    /// na construção para o `C_Encrypt` (cifra local, PKCS#1 v1.5) e para a
    /// conferência da chave de teste não reparsearem o DER a cada chamada.
    /// `None` só se o SPKI não for RSA, caso em que o token também não publica
    /// os objetos de chave.
    pub publica: Option<rsa::RsaPublicKey>,
    /// Chave de assinatura, opcional. Presente apenas em modo de teste — ver
    /// `caminho_chave_teste`. Em produção a chave privada NUNCA está aqui: ela
    /// vive no HSM da Certisign e o `C_Sign` a chamará via daemon.
    pub chave_teste: Option<ChaveInstalacao>,
}

impl Token {
    /// Lê o estado local e monta o token. `Ok(None)` quer dizer "instalação
    /// ainda não preparada": o slot existe, mas sem token dentro.
    ///
    /// Note que isto NÃO vai à rede e NÃO pede PIN. É de propósito: o
    /// certificado é dado público, e um módulo PKCS#11 é carregado dentro do
    /// processo alheio (Papers, Firefox), onde bloquear em I/O de rede na
    /// enumeração de slots é o caminho mais curto para travar a UI do
    /// hospedeiro.
    pub fn carregar() -> Result<Option<Token>, String> {
        let dir = remoteid_caminhos::dir_dados();
        let caminho = remoteid_caminhos::caminho_estado(&dir);
        let estado =
            remoteid_store_json::ler(&caminho).map_err(|e| format!("state.json ilegível: {e}"))?;

        let Some(cert) = estado.certificados.first() else {
            return Ok(None);
        };
        let Some(b64) = cert.base64.as_deref() else {
            // Registrado, mas a carteira ainda não trouxe o DER.
            return Ok(None);
        };
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| format!("certificado da carteira não é base64: {e}"))?;

        let mut token = Token::do_certificado(&der, &cert.serial_number)?;
        // A cadeia é um extra: uma AC ilegível no state.json não pode tirar o
        // certificado do titular do ar. As que não decodificam ficam de fora.
        let autoridades: Vec<Vec<u8>> = cert
            .cadeia
            .iter()
            .filter_map(|b| {
                base64::engine::general_purpose::STANDARD
                    .decode(b.trim())
                    .ok()
            })
            .collect();
        token.publicar_autoridades(&autoridades);

        // Modo de teste: se `chave-assinatura.pem` estiver no diretório de
        // dados, o módulo assina localmente com ela. É o que permite validar a
        // cadeia inteira (Papers → poppler → NSS → módulo → assinatura) com um
        // certificado autoassinado, sem tocar no HSM nem gastar OTP. Em
        // produção este arquivo não existe — o `C_Sign` real ainda não está
        // implementado e vai passar pelo motor.
        let caminho_chave = caminho_chave_teste(&dir);
        if caminho_chave.exists() {
            match remoteid_chave_pem::carregar(&caminho_chave) {
                Ok(chave) => token.instalar_chave_teste(chave)?,
                Err(e) => return Err(format!("chave-assinatura.pem ilegível: {e}")),
            }
        }

        Ok(Some(token))
    }

    /// Valida que a chave local de teste corresponde ao certificado e a instala
    /// para o `C_Sign` assinar localmente.
    ///
    /// Os OBJETOS `CKO_PUBLIC_KEY`/`CKO_PRIVATE_KEY` NÃO são criados aqui: eles
    /// já foram publicados por [`Token::do_certificado`], derivados do próprio
    /// certificado, e existem SEMPRE (com ou sem chave local) — senão o
    /// `C_SignInit` barra e o modo de produção (assinar via socket do app)
    /// nunca funcionaria. Aqui só validamos a correspondência e guardamos a
    /// chave: se ela não bate com o certificado, a assinatura sairia e o
    /// hospedeiro a rejeitaria ao verificar contra a chave pública do cert.
    fn instalar_chave_teste(&mut self, chave: ChaveInstalacao) -> Result<(), String> {
        use rsa::traits::PublicKeyParts as _;

        let publica = self
            .publica
            .as_ref()
            .ok_or("SPKI do certificado não é RSA")?;

        let pub_da_chave = chave.publica();
        if pub_da_chave.n() != publica.n() || pub_da_chave.e() != publica.e() {
            return Err(
                "chave-assinatura.pem não corresponde ao certificado (modulus difere)".into(),
            );
        }

        self.chave_teste = Some(chave);
        Ok(())
    }

    pub fn do_certificado(der: &[u8], serie: &str) -> Result<Token, String> {
        let CamposX509 {
            cert,
            subject,
            issuer,
            serial,
            id,
        } = CamposX509::de(der)?;
        let tbs = &cert.tbs_certificate;

        let rotulo =
            nome_comum(&tbs.subject.to_string()).unwrap_or_else(|| format!("RemoteID {serie}"));

        let mut objetos = vec![Objeto::certificado(
            der.to_vec(),
            subject,
            issuer,
            serial,
            id.clone(),
            rotulo.clone(),
        )];

        // Publica `CKO_PUBLIC_KEY` + `CKO_PRIVATE_KEY` derivados do CERTIFICADO,
        // SEMPRE (com ou sem chave local). Sem a chave privada como objeto, o
        // `C_SignInit` recusa e o hospedeiro nem oferece assinar — então o modo
        // de produção (assinar via socket do app, com a chave real no HSM)
        // nunca funcionaria. O objeto é só o "cabo" que o hospedeiro segura; a
        // assinatura de fato vem da chave local (teste) ou do app (produção).
        // `n`/`e` vêm do SPKI do cert, para baterem byte a byte com o que o
        // hospedeiro já leu; `to_bytes_be()` remove os zeros à esquerda, como o
        // Cryptoki manda.
        let publica = rsa_do_spki_bytes(tbs.subject_public_key_info.subject_public_key.raw_bytes());
        if let Some(publica) = &publica {
            use rsa::traits::PublicKeyParts as _;
            let modulo = publica.n().to_bytes_be();
            let expoente = publica.e().to_bytes_be();
            let rotulo_bytes = rotulo.clone().into_bytes();
            objetos.push(Objeto::chave_publica(
                modulo.clone(),
                expoente.clone(),
                id.clone(),
                rotulo_bytes.clone(),
            ));
            objetos.push(Objeto::chave_privada(modulo, expoente, id, rotulo_bytes));
        }

        Ok(Token {
            rotulo,
            serie: serie.to_string(),
            objetos,
            publica,
            chave_teste: None,
        })
    }

    /// Publica as autoridades da cadeia como `CKO_CERTIFICATE`, ao lado do
    /// certificado do titular (issue 22). `ders` vem na ordem da cadeia.
    ///
    /// Os objetos do titular continuam primeiro: há hospedeiro que pega o
    /// primeiro certificado de um `C_FindObjects` e assume que é o do titular.
    /// Uma AC que não decodifica é pulada; as outras entram.
    pub fn publicar_autoridades(&mut self, ders: &[Vec<u8>]) {
        let mut handle = HANDLE_PRIMEIRA_AUTORIDADE;
        for der in ders {
            let Ok(campos) = CamposX509::de(der) else {
                continue;
            };
            let rotulo = nome_comum(&campos.cert.tbs_certificate.subject.to_string())
                .unwrap_or_else(|| "Autoridade certificadora".to_string());
            self.objetos.push(Objeto::autoridade(
                handle,
                der.clone(),
                campos.subject,
                campos.issuer,
                campos.serial,
                campos.id,
                rotulo,
            ));
            handle += 1;
        }
    }

    pub fn objeto(&self, handle: CK_OBJECT_HANDLE) -> Option<&Objeto> {
        self.objetos.iter().find(|o| o.handle == handle)
    }

    /// Handles dos objetos que casam com o template de busca.
    pub fn buscar(&self, gabarito: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Vec<CK_OBJECT_HANDLE> {
        self.objetos
            .iter()
            .filter(|o| o.casa(gabarito))
            .map(|o| o.handle)
            .collect()
    }
}

/// Os atributos de um `CKO_CERTIFICATE` que saem do próprio X.509.
struct CamposX509 {
    cert: Certificate,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
    id: Vec<u8>,
}

impl CamposX509 {
    fn de(der: &[u8]) -> Result<CamposX509, String> {
        let cert = Certificate::from_der(der).map_err(|e| format!("X.509 inválido: {e}"))?;
        let tbs = &cert.tbs_certificate;
        let subject = tbs.subject.to_der().map_err(|e| format!("subject: {e}"))?;
        let issuer = tbs.issuer.to_der().map_err(|e| format!("issuer: {e}"))?;
        // CKA_SERIAL_NUMBER é o DER do INTEGER, não o número em texto. O NSS
        // compara byte a byte com o que extrai do certificado; texto aqui faz o
        // par certificado/chave nunca casar.
        let serial = tbs
            .serial_number
            .to_der()
            .map_err(|e| format!("serial: {e}"))?;
        let spki = tbs
            .subject_public_key_info
            .to_der()
            .map_err(|e| format!("SPKI: {e}"))?;
        // CKA_ID só precisa ser estável e igual entre o certificado e a chave
        // que um dia vai ao lado dele: o NSS o usa como par, não o interpreta.
        // Derivar do SPKI garante isso sem depender de o certificado trazer a
        // extensão SubjectKeyIdentifier, e dá a cada AC um id que não é o do
        // titular (chaves diferentes, SPKIs diferentes).
        let id = Sha256::digest(&spki)[..20].to_vec();
        Ok(CamposX509 {
            cert,
            subject,
            issuer,
            serial,
            id,
        })
    }
}

/// Primeiro `CN=` de um DN em RFC 4514, que é o que o `x509-cert` imprime.
///
/// O Display do `Name` sai com o RDN mais específico primeiro, então o primeiro
/// `CN=` é o do titular e não o de alguma AC no meio do DN.
fn nome_comum(dn: &str) -> Option<String> {
    for parte in dn.split(',') {
        let parte = parte.trim();
        if let Some(v) = parte.strip_prefix("CN=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Onde a chave de teste é procurada. É separado do `installation-key.pem`
/// (que autentica os requests ao RemoteID) de propósito: em produção este
/// arquivo NÃO EXISTE, porque a chave da assinatura mora no HSM.
pub fn caminho_chave_teste(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("chave-assinatura.pem")
}

/// A chave pública RSA a partir dos bytes PKCS#1 do `subjectPublicKey` (o
/// conteúdo do BIT STRING do SPKI). `None` se o SPKI não for RSA.
fn rsa_do_spki_bytes(pkcs1_der: &[u8]) -> Option<rsa::RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    rsa::RsaPublicKey::from_pkcs1_der(pkcs1_der).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objetos::{HANDLE_CERTIFICADO, HANDLE_CHAVE_PRIVADA, HANDLE_CHAVE_PUBLICA};

    #[test]
    fn cn_sai_do_dn_em_rfc4514() {
        let dn = "CN=FULANO DE TAL:12345678901, OU=AC OAB, O=ICP-Brasil, C=BR";
        assert_eq!(nome_comum(dn).unwrap(), "FULANO DE TAL:12345678901");
    }

    #[test]
    fn dn_sem_cn_nao_inventa_rotulo() {
        assert!(nome_comum("OU=AC OAB, O=ICP-Brasil, C=BR").is_none());
    }

    // A cadeia SINTÉTICA do mock: titular → AC TESTE DESKTOPID → raiz.
    const TITULAR: &[u8] = include_bytes!("../../remoteid-mock/fixtures/fake-cert.der");
    const PACOTE: &[u8] = include_bytes!("../../remoteid-mock/fixtures/AC_TESTE_DESKTOPID.p7c");

    fn token_com_cadeia() -> Token {
        let cadeia = remoteid_cadeia::montar(
            TITULAR,
            &remoteid_cadeia::certificados_do_pacote(PACOTE).unwrap(),
        )
        .unwrap();
        assert_eq!(cadeia.autoridades.len(), 2);
        let mut token = Token::do_certificado(TITULAR, "SERIE").unwrap();
        token.publicar_autoridades(&cadeia.autoridades);
        token
    }

    fn atributo(token: &Token, handle: CK_OBJECT_HANDLE, tipo: CK_ATTRIBUTE_TYPE) -> Vec<u8> {
        token
            .objeto(handle)
            .unwrap()
            .atributo(tipo)
            .unwrap()
            .valor
            .clone()
    }

    #[test]
    fn a_cadeia_se_percorre_pelo_subject_como_o_sunpkcs11_faz() {
        // O `P11KeyStore.loadChain`: a partir do certificado final, procura
        // `CKA_CLASS = CKO_CERTIFICATE, CKA_SUBJECT = <issuer do anterior>`
        // até chegar à autoassinada. Tem de andar dois passos e parar.
        let token = token_com_cadeia();
        let classe = (CKA_CLASS, CKO_CERTIFICATE.to_ne_bytes().to_vec());
        let mut atual = HANDLE_CERTIFICADO;
        let mut caminho = vec![];
        loop {
            let emissor = atributo(&token, atual, CKA_ISSUER);
            if emissor == atributo(&token, atual, CKA_SUBJECT) {
                break;
            }
            let achados = token.buscar(&[classe.clone(), (CKA_SUBJECT, emissor)]);
            assert_eq!(achados.len(), 1, "um emissor por passo");
            atual = achados[0];
            caminho.push(atual);
        }
        assert_eq!(
            caminho,
            vec![HANDLE_PRIMEIRA_AUTORIDADE, HANDLE_PRIMEIRA_AUTORIDADE + 1]
        );
    }

    #[test]
    fn as_autoridades_sao_ac_e_nao_pareiam_com_a_chave() {
        let token = token_com_cadeia();
        let id_titular = atributo(&token, HANDLE_CERTIFICADO, CKA_ID);
        for h in [HANDLE_PRIMEIRA_AUTORIDADE, HANDLE_PRIMEIRA_AUTORIDADE + 1] {
            assert_eq!(
                atributo(&token, h, CKA_CERTIFICATE_CATEGORY),
                CK_CERTIFICATE_CATEGORY_AUTHORITY.to_ne_bytes()
            );
            assert_eq!(atributo(&token, h, CKA_TRUSTED), vec![CK_FALSE]);
            assert_ne!(atributo(&token, h, CKA_ID), id_titular);
        }
        // Buscar pelo CKA_ID do titular continua achando só o trio dele.
        let mut do_titular = token.buscar(&[(CKA_ID, id_titular)]);
        do_titular.sort();
        assert_eq!(
            do_titular,
            vec![
                HANDLE_CERTIFICADO,
                HANDLE_CHAVE_PRIVADA,
                HANDLE_CHAVE_PUBLICA
            ]
        );
        assert_eq!(
            atributo(&token, HANDLE_PRIMEIRA_AUTORIDADE, CKA_LABEL),
            b"AC TESTE DESKTOPID"
        );
    }

    #[test]
    fn o_certificado_do_titular_continua_o_primeiro_da_busca() {
        let token = token_com_cadeia();
        let certs = token.buscar(&[(CKA_CLASS, CKO_CERTIFICATE.to_ne_bytes().to_vec())]);
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0], HANDLE_CERTIFICADO);
    }

    #[test]
    fn autoridade_ilegivel_e_pulada_sem_derrubar_as_outras() {
        let mut token = Token::do_certificado(TITULAR, "SERIE").unwrap();
        let certs = remoteid_cadeia::certificados_do_pacote(PACOTE).unwrap();
        token.publicar_autoridades(&[b"lixo".to_vec(), certs[0].clone()]);
        let achados = token.buscar(&[(CKA_CLASS, CKO_CERTIFICATE.to_ne_bytes().to_vec())]);
        assert_eq!(
            achados,
            vec![HANDLE_CERTIFICADO, HANDLE_PRIMEIRA_AUTORIDADE]
        );
    }
}
