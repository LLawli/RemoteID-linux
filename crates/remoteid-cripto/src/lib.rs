//! Chave da instalação: o par RSA que identifica ESTE desktop no RemoteID.
//!
//! O app oficial usa `certi::signer::ArchiveRepository::generateKeyPair` sobre
//! um OpenSSL estaticamente linkado. Aqui é RSA puro em Rust, para o motor não
//! depender do binário `openssl` no PATH (o módulo PKCS#11 futuro não vai poder
//! chamar um subprocesso a cada `C_Sign`).
//!
//! A chave pública vai para o servidor no registro, em **PEM completo**
//! (`-----BEGIN PUBLIC KEY-----`, SubjectPublicKeyInfo). Base64 do DER cru é
//! recusado com ConstraintViolation.

use base64::Engine as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use remoteid_tipos::{Error, Result};

pub const KEY_BITS: usize = 2048;

/// SHA-256 de um buffer.
pub fn sha256(dados: &[u8]) -> [u8; 32] {
    Sha256::digest(dados).into()
}

/// Base64 padrão (com padding), que é o que o protocolo usa em todo lugar.
pub fn b64(dados: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(dados)
}

/// Decodifica base64 padrão.
pub fn de_b64(texto: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(texto.trim())
        .map_err(|e| Error::cripto(format!("base64 inválido: {e}")))
}

/// A chave privada desta instalação.
pub struct ChaveInstalacao {
    inner: RsaPrivateKey,
}

impl ChaveInstalacao {
    /// Gera um par RSA novo (sem tocar em disco). Quem persiste é a borda de
    /// I/O (a fachada `crate::chave` no core, futuro adaptador `chave-pem`).
    pub fn gerar() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let inner = RsaPrivateKey::new(&mut rng, KEY_BITS)
            .map_err(|e| Error::cripto(format!("não gerou a chave RSA: {e}")))?;
        Ok(Self { inner })
    }

    /// Serializa a chave privada em PKCS#8 PEM, para a borda gravar em disco.
    /// Chaves novas são sempre gravadas em PKCS#8 (a leitura aceita PKCS#1 por
    /// compatibilidade com o `openssl genrsa` do harness antigo, ver [`Self::de_pem`]).
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.inner
            .to_pkcs8_pem(LineEnding::LF)
            .map(|z| z.to_string())
            .map_err(|e| Error::cripto(format!("não serializou a chave: {e}")))
    }

    /// Carrega a chave de um PEM já em memória (PKCS#8 ou PKCS#1). Usado pelo
    /// servidor mock de teste, que embute a chave falsa com `include_str!` e
    /// não tem um arquivo em disco para apontar.
    pub fn de_pem(pem: &str) -> Result<Self> {
        let inner = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| Error::cripto(format!("PEM não é chave RSA (PKCS#8 nem PKCS#1): {e}")))?;
        Ok(Self { inner })
    }

    /// Chave pública em PEM completo — o formato que o registro exige.
    pub fn publica_pem(&self) -> Result<String> {
        RsaPublicKey::from(&self.inner)
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::cripto(format!("não serializou a chave pública: {e}")))
    }

    /// Assina um digest JÁ CALCULADO, RSA PKCS#1 v1.5 sobre SHA-256.
    ///
    /// É o `signDigestUsingKeyId` do app: 256 bytes para uma chave de 2048 bits.
    pub fn assinar_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign(Pkcs1v15Sign::new::<Sha256>(), digest)
            .map_err(|e| Error::cripto(format!("falha ao assinar: {e}")))
    }

    /// PKCS#1 v1.5 CRU: só o padding, sem inserir o DigestInfo.
    ///
    /// É o contrato do `CKM_RSA_PKCS` do PKCS#11 — quem chama já mandou o
    /// DigestInfo pronto (é o que o poppler faz ao assinar PDF) ou dados
    /// arbitrários. NÃO usar isto para o protocolo RemoteID: lá o HSM aplica o
    /// DigestInfo do SHA-256, e é [`Self::assinar_digest`] que reproduz aquilo.
    pub fn assinar_pkcs1_v15_cru(&self, dados: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign(Pkcs1v15Sign::new_unprefixed(), dados)
            .map_err(|e| Error::cripto(format!("falha ao assinar (cru): {e}")))
    }

    /// A chave pública correspondente, para quem precisa extrair `n` e `e`.
    pub fn publica(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.inner)
    }

    /// O valor do header `Authorization: Bearer <...>` para um corpo.
    ///
    /// `base64(RSA_sign(SHA256(canonical(corpo))))`, que é a cadeia
    /// `FUN_1000253aa` → `signContentUsingKeyId` → `Base64::fromBinaryToBase64`
    /// do binário oficial.
    pub fn bearer_assinado(&self, canonical: &str) -> Result<String> {
        let digest = sha256(canonical.as_bytes());
        Ok(b64(&self.assinar_digest(&digest)?))
    }

    /// Confere uma assinatura contra a própria chave. Usado nos testes.
    pub fn verificar(&self, digest: &[u8], assinatura: &[u8]) -> bool {
        RsaPublicKey::from(&self.inner)
            .verify(Pkcs1v15Sign::new::<Sha256>(), digest, assinatura)
            .is_ok()
    }
}

/// Verifica uma assinatura contra a chave pública de um certificado X.509 (DER).
///
/// É esta função que transforma "recebi 256 bytes do servidor" em "o HSM
/// assinou o MEU digest com o certificado do titular". Foi essa verificação,
/// feita à mão com `openssl pkeyutl -verify` em 02/09/2026, que fechou a
/// validação do protocolo; aqui ela vira parte do harness.
///
/// `Err` quer dizer "não deu para verificar" (certificado ilegível ou de outro
/// algoritmo), que é diferente de `Ok(false)`, "a assinatura não confere".
/// Confundir os dois faria o harness acusar fraude onde só houve um parse ruim.
pub fn verificar_com_certificado(
    cert_der: &[u8],
    digest: &[u8],
    assinatura: &[u8],
) -> Result<bool> {
    use rsa::pkcs8::DecodePublicKey;
    use x509_cert::der::{Decode, Encode};

    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| Error::cripto(format!("certificado X.509 ilegível: {e}")))?;
    // Reserializar o SPKI e deixar o `rsa` decodificá-lo evita depender de uma
    // conversão direta entre as versões de tipo dos dois crates.
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::cripto(format!("SubjectPublicKeyInfo ilegível: {e}")))?;
    let publica = RsaPublicKey::from_public_key_der(&spki)
        .map_err(|e| Error::cripto(format!("a chave do certificado não é RSA: {e}")))?;

    Ok(publica
        .verify(Pkcs1v15Sign::new::<Sha256>(), digest, assinatura)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assina_digest_com_256_bytes_e_verifica() {
        let chave = ChaveInstalacao::gerar().unwrap();

        // O tamanho importa: a signatureBase64 do servidor tem 256 bytes pelo
        // mesmo motivo (RSA-2048), e é isso que o C_Sign do PKCS#11 devolve.
        let digest = sha256(b"canonical de teste");
        let sig = chave.assinar_digest(&digest).unwrap();
        assert_eq!(sig.len(), 256);
        assert!(chave.verificar(&digest, &sig));

        // Determinístico: PKCS#1 v1.5 não tem sal, então o mesmo corpo dá o
        // mesmo Bearer. É o que permite reproduzir um request num bug report.
        let a = chave.bearer_assinado("mesmo corpo").unwrap();
        let b = chave.bearer_assinado("mesmo corpo").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, chave.bearer_assinado("outro corpo").unwrap());
    }

    #[test]
    fn chave_gerada_serializa_e_reabre_igual() {
        // A chave nova sai em PKCS#8 PEM, e reabri-la pelo PEM dá a mesma chave
        // pública. É o contrato de que a borda de I/O depende para persistir.
        let chave = ChaveInstalacao::gerar().unwrap();
        let pem = chave.to_pkcs8_pem().unwrap();
        assert!(pem.contains("PRIVATE KEY"));
        let reaberta = ChaveInstalacao::de_pem(&pem).unwrap();
        assert_eq!(
            chave.publica_pem().unwrap(),
            reaberta.publica_pem().unwrap()
        );
        assert!(chave
            .publica_pem()
            .unwrap()
            .starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    /// Forja um certificado autoassinado com a chave dada, para poder testar a
    /// verificação sem depender do HSM da Certisign.
    fn certificado_de_teste(chave: &RsaPrivateKey) -> Vec<u8> {
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::der::Encode;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let assinador = rsa::pkcs1v15::SigningKey::<Sha256>::new(chave.clone());
        let spki = SubjectPublicKeyInfoOwned::from_key(RsaPublicKey::from(chave)).unwrap();
        let construtor = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(std::time::Duration::from_secs(3600)).unwrap(),
            Name::from_str("CN=Titular de Teste").unwrap(),
            spki,
            &assinador,
        )
        .unwrap();
        construtor.build().unwrap().to_der().unwrap()
    }

    #[test]
    fn verifica_assinatura_contra_o_certificado() {
        let mut rng = rand::thread_rng();
        let chave = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let der = certificado_de_teste(&chave);

        let digest = sha256(b"documento");
        let sig = chave.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).unwrap();

        assert!(verificar_com_certificado(&der, &digest, &sig).unwrap());
        // Digest diferente: a assinatura é de outro conteúdo.
        assert!(!verificar_com_certificado(&der, &sha256(b"outro"), &sig).unwrap());
        // Assinatura de outra chave: não é o titular deste certificado.
        let intrusa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let falsa = intrusa
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .unwrap();
        assert!(!verificar_com_certificado(&der, &digest, &falsa).unwrap());
    }

    #[test]
    fn certificado_ilegivel_da_erro_e_nao_false() {
        // "não deu para verificar" não pode virar "não confere": um seria bug
        // de parse, o outro seria acusação de assinatura inválida.
        assert!(
            verificar_com_certificado(b"isto nao e um certificado", &[0u8; 32], &[0u8; 256])
                .is_err()
        );
    }
}
