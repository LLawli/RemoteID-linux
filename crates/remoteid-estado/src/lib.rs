//! Estado da instalação e política de cache de sessão (núcleo puro).
//!
//! O equivalente em memória do `identity.xml` do app oficial. Guarda o que
//! identifica ESTA instalação no RemoteID (`codigoDesktop`), o certificado da
//! carteira, a política de autorização e o cache do `sessionToken` por
//! certificado ([`SessaoCache`]). A chave privada mora ao lado, em arquivo
//! próprio, e nunca entra aqui.
//!
//! Aqui não há I/O: a persistência (ler/gravar o `state.json`, resolver os
//! diretórios XDG) é da borda (o adaptador
//! `remoteid-store-json`). Este crate é só os tipos e as decisões puras
//! (política de cache do `sessionToken`, quebra do `keyName`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use remoteid_autorizacao::Modo;
use remoteid_tipos::{Error, Result};

/// Um certificado da carteira.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificado {
    /// Como o servidor manda: `"<serial>;<issuer DN>"`.
    pub key_name: String,
    /// Parte 0 do `key_name`. Vai no campo `serialNumber` dos payloads.
    pub serial_number: String,
    /// Parte 1 do `key_name`. Vai no campo `issue` dos payloads.
    pub issue: String,
    /// O X.509 em DER, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

impl Certificado {
    /// Quebra o `keyName` da carteira.
    ///
    /// A ordem é a que a decompilação do `openSession` mostra: parte 0 é o
    /// `serialNumber`, parte 1 é o `issue`. O harness já procurou por campos
    /// `emissorCertificado`/`numeroSerieCertificado` na carteira e achava
    /// vazio: esses nomes só existem na resposta do `tokensessao`.
    pub fn do_key_name(key_name: &str, base64: Option<String>) -> Result<Certificado> {
        let (serial, issuer) = key_name.split_once(';').ok_or_else(|| {
            Error::estado(format!(
                "keyName sem ';' (esperado '<serial>;<issuer>'): {key_name}"
            ))
        })?;
        Ok(Certificado {
            key_name: key_name.to_string(),
            serial_number: serial.to_string(),
            issue: issuer.to_string(),
            base64,
        })
    }

    /// A chave do cache do sessionToken. É o próprio `keyName` da carteira
    /// (`serial;issuer`), reconstruído a partir dos dois campos — o servidor
    /// pode um dia entregar um `keyName` com espaços a mais, e ao reconstruir
    /// evitamos que uma diferença cosmética invalide o cache.
    pub fn chave_cache(&self) -> String {
        format!("{};{}", self.serial_number, self.issue)
    }
}

/// Uma entrada de cache do `sessionToken` para UM certificado.
///
/// Sensível: o `token` autoriza assinaturas com o certificado da instalação.
/// Fica em `state.json` (0600), nunca vaza no diag cru.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessaoCache {
    /// O `sessionToken` opaco devolvido pelo `/api/signature/tokensessao`.
    /// Repassado inteiro no `requestHashSessionSignature`.
    pub token: String,
    /// Epoch em segundos parseado do próprio token (penúltimo campo), que é
    /// o tempo de emissão declarado pelo servidor. Se o parser falhar, o
    /// pré-filtro pelo epoch é desativado para esta entrada e a validade é
    /// decidida pelo servidor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitido_em: Option<u64>,
    /// Epoch local em segundos de quando gravamos a entrada, para detectar
    /// drift entre o relógio do cliente e o do servidor. Diferença grande
    /// entre `emitido_em` e `visto_em` sinaliza que um dos dois relógios
    /// está fora — nesse caso o pré-filtro fica ingênuo e a última palavra
    /// é do servidor.
    pub visto_em: u64,
}

/// Formato de token esperado (verbatim do binário oficial, seção "sessionToken (formato)"):
///
/// ```text
/// sessaoAssinatura;<userId>;<issuer DN urlencoded>;<serial>;0;<base64 JWT>;<epoch>;<hmac base64url>
/// ```
///
/// Extrai o penúltimo campo. Devolve `None` para tokens que não caibam nesse
/// formato — não é erro, é sinal para o cliente cair no fluxo pessimista
/// (deixar o servidor ser a autoridade sobre validade).
pub fn epoch_do_token(token: &str) -> Option<u64> {
    let campos: Vec<&str> = token.split(';').collect();
    // Mínimo: precisa de pelo menos dois campos para haver "penúltimo".
    if campos.len() < 2 {
        return None;
    }
    campos[campos.len() - 2].parse::<u64>().ok()
}

impl SessaoCache {
    pub fn novo(token: String, visto_em: u64) -> SessaoCache {
        let emitido_em = epoch_do_token(&token);
        SessaoCache {
            token,
            emitido_em,
            visto_em,
        }
    }

    /// Verdade se o pré-filtro pelo epoch autoriza uma tentativa.
    ///
    /// - Se o token tem epoch legível E o relógio local é razoável (diferença
    ///   com `emitido_em` menor que 24 h), autoriza se `agora - emitido_em <
    ///   ttl_hipotetico_s`.
    /// - Sem epoch, ou com drift grande, autoriza sempre (o servidor decide).
    pub fn vale_a_pena_tentar(&self, agora: u64, ttl_hipotetico_s: u64) -> bool {
        let Some(emitido) = self.emitido_em else {
            return true;
        };
        let drift = agora.abs_diff(self.visto_em);
        if drift > 24 * 3600 {
            return true;
        }
        agora.saturating_sub(emitido) < ttl_hipotetico_s
    }
}

/// O que persiste entre execuções.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Estado {
    // --- do login ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizacao_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpf: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    // --- do registro ---
    /// O UUID que identifica esta instalação. Vai no path da carteira e do
    /// statusCelular, e no corpo do tokensessao.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codigo_desktop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nome_desktop: Option<String>,

    // --- da carteira ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificados: Vec<Certificado>,

    /// Capacidade informada pelo `statusCelular`. É só informativo: o app
    /// oficial lê esse booleano e o descarta (ver [`remoteid_autorizacao`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usuario_possui_codigo_push: Option<bool>,

    /// Política local de autorização, o equivalente do `AuthorizationMode` do
    /// `identity.xml`. Não vem do servidor.
    #[serde(default = "modo_padrao")]
    pub auth_mode: String,

    /// Cache do `sessionToken` por certificado (chave = [`Certificado::chave_cache`]).
    ///
    /// BTreeMap para serializar em ordem estável e não gerar diff no
    /// `state.json` só por reordenação. O motor usa via [`Estado::sessao`],
    /// [`Estado::guardar_sessao`] e [`Estado::invalidar_sessao`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sessoes: BTreeMap<String, SessaoCache>,

    /// Certificado padrão escolhido pelo usuário, quando a carteira tem mais de
    /// um (a [`Certificado::chave_cache`] dele). É o que [`Estado::certificado`]
    /// devolve; sem escolha, ou se o escolhido saiu da carteira, cai no
    /// primeiro. É uma preferência local, não vem do servidor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificado_ativo: Option<String>,
}

fn modo_padrao() -> String {
    Modo::default().como_str().to_string()
}

impl Estado {
    /// Um estado vazio, já no modo de autorização padrão. É o que a borda
    /// devolve quando não há `state.json` ainda.
    pub fn novo() -> Estado {
        Estado {
            auth_mode: modo_padrao(),
            ..Default::default()
        }
    }

    pub fn modo(&self) -> Modo {
        self.auth_mode.parse().unwrap_or_default()
    }

    /// O certificado a usar na assinatura.
    ///
    /// Se o usuário escolheu um padrão ([`Estado::certificado_ativo`]) e ele
    /// ainda está na carteira, é esse; senão, o primeiro. A escolha some sozinha
    /// se a carteira for refeita e o certificado escolhido não vier mais.
    pub fn certificado(&self) -> Result<&Certificado> {
        if self.certificados.is_empty() {
            return Err(Error::estado(
                "nenhum certificado no estado local: rode `carteira` depois do registro",
            ));
        }
        if let Some(chave) = &self.certificado_ativo {
            if let Some(c) = self
                .certificados
                .iter()
                .find(|c| &c.chave_cache() == chave || &c.key_name == chave)
            {
                return Ok(c);
            }
        }
        Ok(&self.certificados[0])
    }

    /// Define o certificado padrão para assinatura (a `chave_cache` dele). O
    /// motor persiste depois. Não valida aqui se a chave existe na carteira:
    /// [`Estado::certificado`] já cai no primeiro se a escolha não bater.
    pub fn definir_certificado_ativo(&mut self, chave_cache: impl Into<String>) {
        self.certificado_ativo = Some(chave_cache.into());
    }

    /// A `chave_cache` do certificado ativo escolhido, se houver.
    pub fn certificado_ativo(&self) -> Option<&str> {
        self.certificado_ativo.as_deref()
    }

    pub fn codigo_desktop(&self) -> Result<&str> {
        self.codigo_desktop.as_deref().ok_or_else(|| {
            Error::estado("esta instalação ainda não foi registrada: rode `registrar`")
        })
    }

    /// Sessão em cache para este certificado, se o pré-filtro pelo epoch a
    /// aprovar. Não estende o cache: o próprio servidor pode ter uma janela
    /// mais curta, e a última palavra continua sendo dele.
    pub fn sessao(
        &self,
        cert_key: &str,
        agora: u64,
        ttl_hipotetico_s: u64,
    ) -> Option<&SessaoCache> {
        self.sessoes
            .get(cert_key)
            .filter(|s| s.vale_a_pena_tentar(agora, ttl_hipotetico_s))
    }

    /// Grava (ou substitui) o cache para um certificado.
    pub fn guardar_sessao(&mut self, cert_key: String, token: String, agora: u64) {
        self.sessoes
            .insert(cert_key, SessaoCache::novo(token, agora));
    }

    /// Remove o cache de UM certificado. Usado quando o server rejeita a
    /// sessão cached: retiramos e o próximo `sign` pede PIN+OTP.
    pub fn invalidar_sessao(&mut self, cert_key: &str) -> Option<SessaoCache> {
        self.sessoes.remove(cert_key)
    }

    /// Zera todo o cache de sessões. Usado no reset leve global e antes de
    /// operações que refazem a carteira.
    pub fn invalidar_todas_sessoes(&mut self) {
        self.sessoes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quebra_o_key_name_na_ordem_certa() {
        let kn = "12CC6B560ECE122AC1047AA7BE71DBC3;CN=AC OAB G3, O=ICP-Brasil, C=BR";
        let c = Certificado::do_key_name(kn, None).unwrap();
        // Serial primeiro, emissor depois: é a ordem do split no binário.
        assert_eq!(c.serial_number, "12CC6B560ECE122AC1047AA7BE71DBC3");
        assert_eq!(c.issue, "CN=AC OAB G3, O=ICP-Brasil, C=BR");
    }

    #[test]
    fn key_name_sem_ponto_e_virgula_falha_em_vez_de_adivinhar() {
        assert!(Certificado::do_key_name("soserial", None).is_err());
    }

    #[test]
    fn issuer_com_ponto_e_virgula_no_dn_nao_e_partido_de_novo() {
        // split_once, não split: o DN pode conter ';'.
        let c = Certificado::do_key_name("SER;CN=A;OU=B", None).unwrap();
        assert_eq!(c.serial_number, "SER");
        assert_eq!(c.issue, "CN=A;OU=B");
    }

    #[test]
    fn chave_de_cache_e_o_key_name_canonico() {
        let c = Certificado::do_key_name("SER;CN=A;OU=B", None).unwrap();
        assert_eq!(c.chave_cache(), "SER;CN=A;OU=B");
    }

    #[test]
    fn epoch_sai_do_penultimo_campo() {
        // Formato verbatim: sessaoAssinatura;user;issuer;serial;0;jwt;epoch;hmac
        let t = "sessaoAssinatura;327989;CN%3DAC;SER;0;eyJhb;1756900000;abcHMAC";
        assert_eq!(epoch_do_token(t), Some(1756900000));
    }

    #[test]
    fn epoch_none_em_token_malformado_em_vez_de_panic() {
        assert_eq!(epoch_do_token("naoehtoken"), None);
        assert_eq!(epoch_do_token(""), None);
        assert_eq!(epoch_do_token(";;;naoEpoch;abc"), None);
    }

    #[test]
    fn cache_valido_dentro_do_ttl() {
        let agora = 1_756_900_100;
        let s = SessaoCache::novo(format!("x;y;z;serial;0;jwt;{};hmac", 1_756_900_000), agora);
        // Emitido 100s atrás, TTL de 900s: passa.
        assert!(s.vale_a_pena_tentar(agora, 900));
    }

    #[test]
    fn cache_invalido_alem_do_ttl() {
        let emitido = 1_756_800_000;
        let agora = emitido + 4000; // 66 min depois
        let s = SessaoCache::novo(format!("a;b;c;d;0;e;{emitido};f"), agora);
        assert!(!s.vale_a_pena_tentar(agora, 900));
    }

    #[test]
    fn drift_grande_desativa_o_prefiltro_e_deixa_o_server_decidir() {
        // Servidor em 2026, cliente em 2001 (relógio zoado): o pré-filtro
        // seria enganado. Neste caso a última palavra é do servidor.
        let emitido = 1_756_800_000;
        let agora_local = 1_000_000_000; // ~2001
        let s = SessaoCache {
            token: "x".into(),
            emitido_em: Some(emitido),
            visto_em: agora_local,
        };
        assert!(s.vale_a_pena_tentar(agora_local, 60));
    }

    #[test]
    fn cache_sem_epoch_extraivel_deixa_o_server_decidir() {
        let s = SessaoCache {
            token: "opaco".into(),
            emitido_em: None,
            visto_em: 42,
        };
        assert!(s.vale_a_pena_tentar(42, 1));
    }

    #[test]
    fn estado_novo_ja_nasce_no_modo_local() {
        let e = Estado::novo();
        assert_eq!(e.modo(), Modo::Local);
        assert!(e.codigo_desktop().is_err());
    }

    #[test]
    fn sessao_por_certificado_e_a_chave_do_cert() {
        let mut e = Estado::default();
        e.guardar_sessao("SER;CN=A".into(), "tok1".into(), 100);
        e.guardar_sessao("OUT;CN=B".into(), "tok2".into(), 100);

        // Sem epoch parseável: o pré-filtro deixa passar.
        assert_eq!(e.sessao("SER;CN=A", 100, 900).unwrap().token, "tok1");
        assert_eq!(e.sessao("OUT;CN=B", 100, 900).unwrap().token, "tok2");
        assert!(e.sessao("nao_existe", 100, 900).is_none());
    }

    #[test]
    fn invalidar_uma_sessao_nao_afeta_as_outras() {
        let mut e = Estado::default();
        e.guardar_sessao("A".into(), "t1".into(), 1);
        e.guardar_sessao("B".into(), "t2".into(), 1);
        e.invalidar_sessao("A");
        assert!(e.sessao("A", 1, 900).is_none());
        assert!(e.sessao("B", 1, 900).is_some());
    }

    #[test]
    fn certificado_ativo_escolhe_o_certo_ou_cai_no_primeiro() {
        let mut e = Estado {
            certificados: vec![
                Certificado::do_key_name("AAA;CN=AC1", None).unwrap(),
                Certificado::do_key_name("BBB;CN=AC2", None).unwrap(),
            ],
            ..Default::default()
        };
        // Sem escolha: o primeiro.
        assert_eq!(e.certificado().unwrap().serial_number, "AAA");
        // Escolhendo o segundo (pela chave_cache): passa a ser ele.
        e.definir_certificado_ativo("BBB;CN=AC2");
        assert_eq!(e.certificado().unwrap().serial_number, "BBB");
        assert_eq!(e.certificado_ativo(), Some("BBB;CN=AC2"));
        // Escolha que não existe mais na carteira: cai no primeiro, sem erro.
        e.definir_certificado_ativo("ZZZ;sumiu");
        assert_eq!(e.certificado().unwrap().serial_number, "AAA");
    }

    #[test]
    fn invalidar_todas_as_sessoes_esvazia_o_cache() {
        // O reset leve global: depois dele, NENHUM certificado pode assinar
        // sem PIN+OTP.
        let mut e = Estado::default();
        e.guardar_sessao("AAA;CN=AC1".into(), "t;1".into(), 10);
        e.guardar_sessao("BBB;CN=AC2".into(), "t;2".into(), 10);
        assert!(e.sessao("AAA;CN=AC1", 10, 900).is_some());
        e.invalidar_todas_sessoes();
        assert!(e.sessoes.is_empty());
        assert!(e.sessao("AAA;CN=AC1", 10, 900).is_none());
        assert!(e.sessao("BBB;CN=AC2", 10, 900).is_none());
    }

    #[test]
    fn guardar_e_ler_sessao_preserva_o_epoch_do_token() {
        // A persistência em disco é testada na borda (remoteid-store-json);
        // aqui garantimos a parte pura: guardar uma sessão parseia o epoch do
        // token e o pré-filtro a considera dentro do TTL.
        let mut e = Estado::default();
        e.guardar_sessao(
            "SER;CN=AC".into(),
            "sessaoAssinatura;327989;CN%3DAC;SER;0;jwt;1756900000;hmac".into(),
            1_756_900_000,
        );
        let s = e.sessao("SER;CN=AC", 1_756_900_000, 900).unwrap();
        assert!(s.token.starts_with("sessaoAssinatura;"));
        assert_eq!(s.emitido_em, Some(1_756_900_000));
    }
}
