//! O motor: dado um hash, um PIN e um OTP, devolve a assinatura.
//!
//! É este objeto que o daemon do app GTK vai expor via PKCS#11. O contrato de
//! [`Motor::assinar_digest`] é deliberadamente o do `C_Sign`: entra um digest,
//! sai o bloco RSA cru de 256 bytes.
//!
//! # O fluxo
//!
//! ```text
//! login ──> registrar ──> carteira ──┐
//!  (JWT)    (codigoDesktop)  (cert)  │
//!                                    v
//!                    tokensessao ──> requestHashSessionSignature
//!                    (sessionToken)   (signatureBase64)
//! ```
//!
//! O `login` é o único passo que usa o JWT no `Authorization`. Do `carteira`
//! em diante o Bearer é a ASSINATURA do corpo com a chave da instalação
//! ([`crate::canonical`]).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::authmode::{Fatores, Modo};
use crate::canonical::canonical;
use crate::config;
use crate::crypto::{b64, de_b64, sha256, ChaveInstalacao};
use crate::diag::Diag;
use crate::error::{Error, Result};
use crate::http::Http;
use crate::protocol;
use crate::state::{self, Certificado, Estado};

/// Onde e como o motor opera.
pub struct Opcoes {
    pub dir_dados: PathBuf,
    pub dir_diag: PathBuf,
    pub remoteid_url: String,
    pub certinext_url: String,
    pub timeout: Duration,
    /// Janela em que o pré-filtro do cache do `sessionToken` (o epoch do
    /// penúltimo campo do token) considera uma entrada "vale a pena tentar".
    /// A validade REAL é do servidor: este número só evita gastar uma
    /// requisição em algo obviamente vencido. 15 minutos é o chute inicial;
    /// a medição ao vivo (task 9) vai ajustar.
    pub ttl_sessao_hipotetico_s: u64,
}

impl Default for Opcoes {
    fn default() -> Self {
        // Os diretórios (`state::dir_dados`/`dir_diag`) já relocam para /tmp em
        // modo de teste (`TEST_URL`), o mesmo que o módulo PKCS#11 usa — então
        // aqui só decidimos as URLs. Em teste elas apontam para o servidor mock
        // (o valor de `TEST_URL`); em produção, para a Certisign. Nada é escrito
        // onde mora a conta real. Ver [[remoteid-teste-local]].
        let (remoteid, certinext) = match std::env::var("TEST_URL").ok().filter(|v| !v.is_empty()) {
            Some(url) => (url.clone(), url),
            None => (config::REMOTEID_URL.to_string(), config::CERTINEXT_URL.to_string()),
        };
        Opcoes {
            dir_dados: state::dir_dados(),
            dir_diag: state::dir_diag(),
            remoteid_url: remoteid,
            certinext_url: certinext,
            timeout: Duration::from_secs(60),
            ttl_sessao_hipotetico_s: 15 * 60,
        }
    }
}

pub struct Motor {
    opcoes: Opcoes,
    pub estado: Estado,
    chave: ChaveInstalacao,
    http: Http,
    diag: Arc<Diag>,
    /// JWT do login. Só serve para o registro, e não é persistido: expira, e
    /// gravá-lo seria guardar uma credencial de sessão sem necessidade.
    jwt: Option<String>,
}

impl Motor {
    pub fn abrir(opcoes: Opcoes) -> Result<Motor> {
        let diag = Arc::new(Diag::abrir(&opcoes.dir_diag));
        let estado = state::carregar(&state::caminho_estado(&opcoes.dir_dados))?;
        let chave = crate::crypto::carregar_ou_gerar(&state::caminho_chave(&opcoes.dir_dados))?;
        // O transporte fala com o diag pela porta `Diagnostico`, não pelo tipo
        // concreto: por isso o `Arc<Diag>` é coagido para `Arc<dyn Diagnostico>`
        // aqui (a canônica, que o motor loga direto, não está na porta e usa o
        // `Diag` concreto guardado em `self.diag`).
        let diag_transporte: Arc<dyn remoteid_portas::Diagnostico> = diag.clone();
        let http = Http::novo(diag_transporte, opcoes.timeout);

        diag.evento(
            "sessao.inicio",
            serde_json::json!({
                "versao": env!("CARGO_PKG_VERSION"),
                "so": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "remoteid": opcoes.remoteid_url,
                "registrado": estado.codigo_desktop.is_some(),
                "auth_mode": estado.auth_mode,
            }),
        );
        Ok(Motor { opcoes, estado, chave, http, diag, jwt: None })
    }

    /// Caminho do log desta execução, para o CLI mostrar num erro.
    pub fn caminho_diag(&self) -> Option<&std::path::Path> {
        self.diag.caminho()
    }

    pub fn salvar_estado(&self) -> Result<()> {
        state::salvar(&self.estado, &state::caminho_estado(&self.opcoes.dir_dados))
    }

    pub fn chave_publica_pem(&self) -> Result<String> {
        self.chave.publica_pem()
    }

    fn url_rid(&self, caminho: &str) -> String {
        format!("{}{}", self.opcoes.remoteid_url.trim_end_matches('/'), caminho)
    }

    fn url_desktop(&self, caminho: &str) -> String {
        format!(
            "{}{}{}{}",
            self.opcoes.certinext_url.trim_end_matches('/'),
            config::CERTINEXT_BASE,
            config::DESKTOP_PREFIX,
            caminho
        )
    }

    /// Bearer dos endpoints de operação: a assinatura da canônica do corpo.
    fn bearer(&self, corpo: &Value, rotulo: &str) -> Result<String> {
        let canon = canonical(corpo);
        let bearer = self.chave.bearer_assinado(&canon)?;
        // A canônica NÃO é gravada crua: no tokensessao ela contém o PIN e o
        // OTP concatenados. Só o hash, que é o que responde "cliente e servidor
        // calcularam a mesma coisa?".
        self.diag.canonica(rotulo, &canon, &bearer);
        Ok(bearer)
    }

    /// Requisição assinada com a chave da instalação.
    fn op(&self, metodo: &str, caminho: &str, corpo: &Value, rotulo: &str) -> Result<Value> {
        let bearer = self.bearer(corpo, rotulo)?;
        self.http
            .requisitar(metodo, &self.url_rid(caminho), Some(corpo), Some(&bearer), rotulo)?
            .ok_json()
    }

    // --- passos do fluxo -------------------------------------------------

    /// Teste de conectividade: a única rota que responde sem nenhum estado.
    pub fn hierarquias(&self) -> Result<Value> {
        self.http
            .requisitar(
                "GET",
                &self.url_desktop(config::EP_LIST_HIERARCHIES),
                None,
                None,
                "listHierarchies",
            )?
            .ok_json()
    }

    /// `login/usrsenha`. Guarda userId/organizacaoId no estado e o JWT em memória.
    pub fn login(&mut self, email: &str, senha: &str) -> Result<()> {
        let corpo = protocol::login(email, senha);
        let data = self
            .http
            .requisitar(
                "POST",
                &self.url_rid(config::EP_RID_LOGIN),
                Some(&corpo),
                None,
                "login",
            )?
            .ok_json()?;

        let token = data
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::estado("login sem o campo `token` na resposta"))?;
        self.jwt = Some(token.to_string());

        self.estado.user_id = data.get("id").and_then(|v| v.as_i64());
        self.estado.organizacao_id = data.get("organizacaoId").and_then(|v| v.as_i64());
        self.estado.nome = texto(&data, "nome");
        self.estado.cpf = texto(&data, "cpf");
        self.estado.email = Some(email.to_string());
        Ok(())
    }

    /// Registra este desktop e guarda o `codigoDesktop`.
    ///
    /// Único passo, além do login, que usa o JWT no `Authorization`.
    pub fn registrar(&mut self, nome_desktop: &str) -> Result<String> {
        let jwt = self
            .jwt
            .clone()
            .ok_or_else(|| Error::uso("registre depois do login (o JWT não persiste)"))?;
        let user_id = self
            .estado
            .user_id
            .ok_or_else(|| Error::estado("sem userId: refaça o login"))?;
        let org_id = self.estado.organizacao_id.unwrap_or(0);

        let corpo = protocol::registrar_desktop(
            nome_desktop,
            &usuario_local(),
            &dominio_rede(),
            &self.chave.publica_pem()?,
        );
        let data = self
            .http
            .requisitar(
                "POST",
                &self.url_rid(&config::ep_registrar_desktop(user_id, org_id)),
                Some(&corpo),
                Some(&jwt),
                "registrar-desktop",
            )?
            .ok_json()?;

        let codigo = texto(&data, "codigoDesktop")
            .ok_or_else(|| Error::estado("registro sem `codigoDesktop` na resposta"))?;
        self.estado.codigo_desktop = Some(codigo.clone());
        self.estado.nome_desktop = Some(nome_desktop.to_string());
        Ok(codigo)
    }

    /// `statusCelular`: diz se a conta tem celular pareado para push.
    ///
    /// É informação de CAPACIDADE, não de modo. O app oficial lê este booleano
    /// e o descarta, gravando `AuthorizationMode = "local"` de qualquer jeito
    /// (ver [`crate::authmode`]). Guardamos o valor para o usuário saber se faz
    /// sentido tentar o push, mas ele não decide nada sozinho.
    pub fn status_celular(&mut self) -> Result<bool> {
        let codigo = self.estado.codigo_desktop()?.to_string();
        let corpo = protocol::momento(agora());
        let data = self.op(
            "POST",
            &config::ep_status_celular(&codigo),
            &corpo,
            "statusCelular",
        )?;
        let tem_push = data
            .get("usuarioPossuiCodigoPush")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        self.estado.usuario_possui_codigo_push = Some(tem_push);
        Ok(tem_push)
    }

    /// `carteira`: baixa os certificados e guarda serial e emissor.
    pub fn carteira(&mut self) -> Result<&[Certificado]> {
        let codigo = self.estado.codigo_desktop()?.to_string();
        let corpo = protocol::momento(agora());
        let data = self.op("POST", &config::ep_carteira(&codigo), &corpo, "carteira")?;

        let lista = data
            .get("certificados")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::estado("carteira sem a lista `certificados`"))?;

        let mut certificados = Vec::new();
        for item in lista {
            let Some(key_name) = item.get("keyName").and_then(|v| v.as_str()) else {
                continue;
            };
            certificados.push(Certificado::do_key_name(key_name, texto(item, "base64"))?);
        }
        if certificados.is_empty() {
            return Err(Error::estado("a carteira veio sem nenhum certificado utilizável (sem `keyName`)"));
        }
        self.estado.certificados = certificados;
        Ok(&self.estado.certificados)
    }

    /// `tokensessao`: abre a sessão de assinatura e devolve o `sessionToken`.
    ///
    /// O token é opaco de propósito. Ele não é um JWT: é um registro com campos
    /// separados por `;`
    /// (`sessaoAssinatura;<userId>;<issuer>;<serial>;0;<jwt em base64>;<epoch>;<hmac>`).
    /// Tentar interpretá-lo aqui só criaria acoplamento com um formato que o
    /// servidor pode mudar; o contrato é repassá-lo inteiro no requestHash.
    pub fn abrir_sessao(&self, fatores: &Fatores) -> Result<String> {
        let modo = self.estado.modo();
        // Recusa cedo a combinação que o app oficial não emite (push com PIN).
        fatores.compativel_com(&modo).map_err(Error::uso)?;

        let codigo = self.estado.codigo_desktop()?;
        let cert = self.estado.certificado()?;
        // No caminho pin+otp o app deixa este campo vazio; a run ao vivo provou
        // que o servidor aceita um nome. No push seguimos o app e preenchemos.
        let nome_app = config::NOME_APLICACAO;
        let corpo = protocol::tokensessao(codigo, cert, fatores, nome_app);

        let rotulo = match fatores {
            Fatores::PinOtp { .. } => "tokensessao (pin+otp)",
            Fatores::Push => "tokensessao (push)",
        };
        let data = self.op("POST", config::EP_RID_SESSION_TOKEN, &corpo, rotulo)?;
        texto(&data, "token")
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::estado("tokensessao respondeu sucesso mas sem `token`"))
    }

    /// `requestHashSessionSignature`: manda o digest e recebe a assinatura.
    ///
    /// Devolve o bloco RSA **cru** (256 bytes para RSA-2048), não um PKCS#7.
    /// Quem quiser assinar PDF/CAdES monta o PKCS#7 em volta disto.
    pub fn assinar_com_sessao(&self, session_token: &str, digest: &[u8]) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            return Err(Error::uso(format!(
                "o digest tem de ser SHA-256 (32 bytes); veio com {}",
                digest.len()
            )));
        }
        let codigo = self.estado.codigo_desktop()?;
        let cert = self.estado.certificado()?;
        let corpo = protocol::request_hash(
            codigo,
            session_token,
            cert,
            "SHA256",
            &[b64(digest)],
        );
        let data = self.op("POST", config::EP_RID_REQUEST_HASH, &corpo, "requestHash")?;

        let item = data
            .get("idArray")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .ok_or_else(|| Error::estado("requestHash sem `idArray`"))?;
        // Cada item do idArray tem o seu próprio status: o pedido pode ter sido
        // aceito e a assinatura daquele hash ter falhado.
        if item.get("status").and_then(|v| v.as_bool()) == Some(false) {
            let msg = texto(item, "message").unwrap_or_else(|| "sem detalhe".into());
            return Err(Error::estado(format!("o HSM recusou o hash: {msg}")));
        }
        let assinatura_b64 = texto(item, "signatureBase64")
            .ok_or_else(|| Error::estado("requestHash sem `signatureBase64`"))?;
        let assinatura = de_b64(&assinatura_b64)?;

        self.diag.evento(
            "assinatura.recebida",
            serde_json::json!({ "bytes": assinatura.len() }),
        );
        Ok(assinatura)
    }

    /// O contrato do motor: digest + fatores → assinatura crua.
    ///
    /// Abre a sessão e assina em seguida, porque o OTP é de uso único e tem
    /// validade de uns 30 segundos: qualquer pausa entre os dois passos é uma
    /// chance de o token nascer velho.
    pub fn assinar_digest(&self, digest: &[u8], fatores: &Fatores) -> Result<Vec<u8>> {
        let token = self.abrir_sessao(fatores)?;
        self.assinar_com_sessao(&token, digest)
    }

    /// Conveniência: assina o SHA-256 de um conteúdo.
    pub fn assinar_conteudo(&self, conteudo: &[u8], fatores: &Fatores) -> Result<Vec<u8>> {
        self.assinar_digest(&sha256(conteudo), fatores)
    }

    /// Fluxo otimista com retry silencioso: **o que o daemon chama**.
    ///
    /// 1. Se há um `sessionToken` em cache pro certificado ativo e o pré-filtro
    ///    pelo epoch autoriza, tenta assinar direto — nenhum prompt, nenhum OTP
    ///    gasto, uma única requisição HTTP.
    /// 2. Se o servidor responder que a sessão não vale
    ///    ([`config::e_falha_de_sessao`]), a entrada é invalidada, `obter_fatores`
    ///    é chamado para pedir PIN+OTP ao usuário, uma nova sessão é aberta e a
    ///    assinatura é refeita. Nada disso vira erro visível: para o hospedeiro
    ///    a única diferença entre os dois caminhos é o tempo.
    /// 3. Se o servidor rejeitar por outro motivo (rede, HSM recusou o hash,
    ///    OTP inválido no reemit), o erro sobe. A UI decide o que dizer.
    ///
    /// `obter_fatores` é fechado à parte porque um daemon com UI pode demorar
    /// segundos (o humano digita), e mantê-lo fora deste método permite testar
    /// o fluxo com um closure sem depender de GTK.
    pub fn assinar_com_cache<F>(&mut self, digest: &[u8], obter_fatores: F) -> Result<Vec<u8>>
    where
        F: FnOnce() -> Result<Fatores>,
    {
        if digest.len() != 32 {
            return Err(Error::uso(format!(
                "o digest tem de ser SHA-256 (32 bytes); veio com {}",
                digest.len()
            )));
        }
        let cert_key = self.estado.certificado()?.chave_cache();
        let agora_s = agora();
        let ttl = self.opcoes.ttl_sessao_hipotetico_s;

        // Tentativa otimista: usa o cache se o pré-filtro autoriza.
        let token_cached = self
            .estado
            .sessao(&cert_key, agora_s, ttl)
            .map(|s| s.token.clone());

        if let Some(token) = token_cached {
            match self.assinar_com_sessao(&token, digest) {
                Ok(bytes) => {
                    self.diag.evento(
                        "assinatura.cache_hit",
                        serde_json::json!({ "cert_key": &cert_key }),
                    );
                    return Ok(bytes);
                }
                Err(Error::Servidor(ref se)) if config::e_falha_de_sessao(&se.message, "") => {
                    self.diag.evento(
                        "assinatura.cache_recusado",
                        serde_json::json!({
                            "cert_key": &cert_key,
                            "mensagem": &se.message,
                        }),
                    );
                    self.estado.invalidar_sessao(&cert_key);
                    self.salvar_estado()?;
                    // cai para o caminho pessimista.
                }
                Err(outro) => return Err(outro),
            }
        }

        // Caminho pessimista: pede fatores, abre sessão nova, assina.
        let fatores = obter_fatores()?;
        let novo_token = self.abrir_sessao(&fatores)?;
        let bytes = self.assinar_com_sessao(&novo_token, digest)?;

        self.estado.guardar_sessao(cert_key.clone(), novo_token, agora());
        self.salvar_estado()?;
        self.diag.evento(
            "assinatura.sessao_nova",
            serde_json::json!({ "cert_key": &cert_key }),
        );
        Ok(bytes)
    }

    /// Invalida o cache do `sessionToken` para o certificado ativo (o "reset
    /// leve" da UI: força a próxima assinatura a pedir PIN+OTP, sem apagar
    /// nada mais).
    pub fn reautorizar_proxima(&mut self) -> Result<()> {
        let cert_key = self.estado.certificado()?.chave_cache();
        self.estado.invalidar_sessao(&cert_key);
        self.salvar_estado()
    }

    /// Zera TODO o cache de sessões. Útil quando a carteira é refeita.
    pub fn invalidar_todas_sessoes(&mut self) -> Result<()> {
        self.estado.invalidar_todas_sessoes();
        self.salvar_estado()
    }

    /// Troca a política local de autorização.
    pub fn definir_modo(&mut self, modo: &Modo) {
        self.estado.auth_mode = modo.como_str().to_string();
    }
}

fn texto(v: &Value, chave: &str) -> Option<String> {
    v.get(chave).and_then(|x| x.as_str()).map(str::to_string)
}

// Fatos de host e relógio moram nos adaptadores de borda (fonte única); o motor
// só delega, até a Fase 3 injetá-los como portas. Instanciar o adaptador aqui é
// barato: ambos são structs sem estado.
fn agora() -> u64 {
    use remoteid_portas::Relogio;
    remoteid_relogio_sistema::RelogioSistema.agora()
}

fn usuario_local() -> String {
    use remoteid_portas::Ambiente;
    remoteid_ambiente_sistema::AmbienteSistema.usuario_local()
}

/// Hostname para `dominioRede`, que NÃO pode ir vazio.
fn dominio_rede() -> String {
    use remoteid_portas::Ambiente;
    remoteid_ambiente_sistema::AmbienteSistema.hostname()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dominio_rede_nunca_volta_vazio() {
        // O servidor recusa com DomainNameLeftBlank.
        assert!(!dominio_rede().is_empty());
    }

    #[test]
    fn usuario_local_nunca_volta_vazio() {
        assert!(!usuario_local().is_empty());
    }
}
