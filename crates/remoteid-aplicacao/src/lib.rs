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
//! ([`remoteid_protocolo_servidor::canonical`]).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use remoteid_portas::{
    Ambiente, CofreDeChave, Diagnostico, Relogio, RepositorioEstado, RequisicaoHttp,
    TransporteRemoteId,
};
use remoteid_tipos::{Error, IdInstalacao, Result};

use remoteid_autorizacao::{Fatores, Modo};
use remoteid_cripto::{b64, de_b64, sha256};
use remoteid_estado::{Certificado, Estado};
use remoteid_protocolo_servidor::canonical::canonical;
use remoteid_protocolo_servidor::{config, protocol, resposta};

// Adaptadores e composição padrão do desktop, montados por `Motor::abrir`. Uma
// outra edição (a central em Postgres) usa `Motor::com_dependencias` e não passa
// por aqui, então não linka estes.
use remoteid_ambiente_sistema::AmbienteSistema;
use remoteid_caminhos as caminhos;
use remoteid_chave_pem::CofrePem;
use remoteid_diag_jsonl::Diag;
use remoteid_http::Http;
use remoteid_relogio_sistema::RelogioSistema;
use remoteid_store_json::RepositorioJson;

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
        // Os diretórios (`caminhos::dir_dados`/`dir_diag`) já relocam para /tmp em
        // modo de teste (`TEST_URL`), o mesmo que o módulo PKCS#11 usa — então
        // aqui só decidimos as URLs. Em teste elas apontam para o servidor mock
        // (o valor de `TEST_URL`); em produção, para a Certisign. Nada é escrito
        // onde mora a conta real. Ver [[remoteid-teste-local]].
        let (remoteid, certinext) = match std::env::var("TEST_URL").ok().filter(|v| !v.is_empty()) {
            Some(url) => (url.clone(), url),
            None => (config::REMOTEID_URL.to_string(), config::CERTINEXT_URL.to_string()),
        };
        Opcoes {
            dir_dados: caminhos::dir_dados(),
            dir_diag: caminhos::dir_diag(),
            remoteid_url: remoteid,
            certinext_url: certinext,
            timeout: Duration::from_secs(60),
            ttl_sessao_hipotetico_s: 15 * 60,
        }
    }
}

/// As portas que o motor consome. A raiz de composição as monta e injeta; o
/// motor não conhece nenhuma implementação concreta. `Motor::abrir` monta as
/// padrão do desktop (JSON, PEM, ureq, JSONL, relógio e ambiente do sistema);
/// uma outra edição (a central em Postgres) monta as suas e chama
/// [`Motor::com_dependencias`].
pub struct Dependencias {
    pub repo: Box<dyn RepositorioEstado>,
    pub cofre: Box<dyn CofreDeChave>,
    pub transporte: Box<dyn TransporteRemoteId>,
    pub diag: Arc<dyn Diagnostico>,
    pub relogio: Box<dyn Relogio>,
    pub ambiente: Box<dyn Ambiente>,
    /// Qual instalação/conta este motor serve. No desktop, [`IdInstalacao::local`].
    pub id: IdInstalacao,
}

pub struct Motor {
    opcoes: Opcoes,
    pub estado: Estado,
    repo: Box<dyn RepositorioEstado>,
    cofre: Box<dyn CofreDeChave>,
    transporte: Box<dyn TransporteRemoteId>,
    diag: Arc<dyn Diagnostico>,
    relogio: Box<dyn Relogio>,
    ambiente: Box<dyn Ambiente>,
    id: IdInstalacao,
    /// JWT do login. Só serve para o registro, e não é persistido: expira, e
    /// gravá-lo seria guardar uma credencial de sessão sem necessidade.
    jwt: Option<String>,
}

impl Motor {
    /// Abre o motor com os adaptadores PADRÃO do desktop, montados a partir de
    /// `opcoes`: estado em JSON e chave em PEM em `dir_dados`, transporte ureq,
    /// diag JSONL em `dir_diag`, relógio e ambiente do sistema, instalação
    /// [`IdInstalacao::local`].
    pub fn abrir(opcoes: Opcoes) -> Result<Motor> {
        let dir = opcoes.dir_dados.clone();
        let diag: Arc<dyn Diagnostico> = Arc::new(Diag::abrir(&opcoes.dir_diag));
        let transporte = Box::new(Http::novo(diag.clone(), opcoes.timeout));
        let deps = Dependencias {
            repo: Box::new(RepositorioJson::novo(dir.clone())),
            cofre: Box::new(CofrePem::novo(dir)),
            transporte,
            diag,
            relogio: Box::new(RelogioSistema),
            ambiente: Box::new(AmbienteSistema),
            id: IdInstalacao::local(),
        };
        let motor = Motor::com_dependencias(opcoes, deps)?;
        // Preserva o comportamento antigo (a chave nasce no abrir do desktop):
        // força a geração agora, para o harness poder afirmar "chave pronta" e
        // para o primeiro registro não pagar a latência da geração.
        motor.cofre.publica_pem(&motor.id)?;
        Ok(motor)
    }

    /// Abre o motor com dependências INJETADAS. É por aqui que uma edição
    /// diferente (central em Postgres, testes com adaptadores em memória) troca
    /// as implementações sem tocar em nada da lógica abaixo.
    pub fn com_dependencias(opcoes: Opcoes, deps: Dependencias) -> Result<Motor> {
        let estado = deps.repo.carregar(&deps.id)?;
        deps.diag.evento(
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
        Ok(Motor {
            opcoes,
            estado,
            repo: deps.repo,
            cofre: deps.cofre,
            transporte: deps.transporte,
            diag: deps.diag,
            relogio: deps.relogio,
            ambiente: deps.ambiente,
            id: deps.id,
            jwt: None,
        })
    }

    /// Caminho do log desta execução, para o CLI mostrar num erro.
    pub fn caminho_diag(&self) -> Option<PathBuf> {
        self.diag.caminho()
    }

    pub fn salvar_estado(&self) -> Result<()> {
        self.repo.salvar(&self.id, &self.estado)
    }

    pub fn chave_publica_pem(&self) -> Result<String> {
        self.cofre.publica_pem(&self.id)
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
        let bearer = self.cofre.bearer_assinado(&self.id, &canon)?;
        // A canônica NÃO é gravada crua: no tokensessao ela contém o PIN e o
        // OTP concatenados. Só o hash, que é o que responde "cliente e servidor
        // calcularam a mesma coisa?".
        self.diag.evento(
            "assinatura",
            serde_json::json!({
                "rotulo": rotulo,
                "canonica_sha256": hex(&sha256(canon.as_bytes())),
                "canonica_bytes": canon.len(),
                "bearer_sha256": hex(&sha256(bearer.as_bytes())),
                "bearer_bytes": bearer.len(),
            }),
        );
        Ok(bearer)
    }

    /// Requisição assinada com a chave da instalação.
    fn op(&self, metodo: &str, caminho: &str, corpo: &Value, rotulo: &str) -> Result<Value> {
        let bearer = self.bearer(corpo, rotulo)?;
        let req = RequisicaoHttp {
            metodo: metodo.to_string(),
            url: self.url_rid(caminho),
            corpo: Some(corpo.clone()),
            bearer: Some(bearer),
            rotulo: rotulo.to_string(),
        };
        let r = self.transporte.requisitar(&req)?;
        resposta::ok_json(r.status, &r.corpo)
    }

    // --- passos do fluxo -------------------------------------------------

    /// Teste de conectividade: a única rota que responde sem nenhum estado.
    pub fn hierarquias(&self) -> Result<Value> {
        let req = RequisicaoHttp {
            metodo: "GET".to_string(),
            url: self.url_desktop(config::EP_LIST_HIERARCHIES),
            corpo: None,
            bearer: None,
            rotulo: "listHierarchies".to_string(),
        };
        let r = self.transporte.requisitar(&req)?;
        resposta::ok_json(r.status, &r.corpo)
    }

    /// `login/usrsenha`. Guarda userId/organizacaoId no estado e o JWT em memória.
    pub fn login(&mut self, email: &str, senha: &str) -> Result<()> {
        let corpo = protocol::login(email, senha);
        let req = RequisicaoHttp {
            metodo: "POST".to_string(),
            url: self.url_rid(config::EP_RID_LOGIN),
            corpo: Some(corpo),
            bearer: None,
            rotulo: "login".to_string(),
        };
        let r = self.transporte.requisitar(&req)?;
        let data = resposta::ok_json(r.status, &r.corpo)?;

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
            &self.ambiente.usuario_local(),
            &self.ambiente.hostname(),
            &self.cofre.publica_pem(&self.id)?,
        );
        let req = RequisicaoHttp {
            metodo: "POST".to_string(),
            url: self.url_rid(&config::ep_registrar_desktop(user_id, org_id)),
            corpo: Some(corpo),
            bearer: Some(jwt),
            rotulo: "registrar-desktop".to_string(),
        };
        let r = self.transporte.requisitar(&req)?;
        let data = resposta::ok_json(r.status, &r.corpo)?;

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
    /// (ver [`remoteid_autorizacao`]). Guardamos o valor para o usuário saber se faz
    /// sentido tentar o push, mas ele não decide nada sozinho.
    pub fn status_celular(&mut self) -> Result<bool> {
        let codigo = self.estado.codigo_desktop()?.to_string();
        let corpo = protocol::momento(self.relogio.agora());
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
        let corpo = protocol::momento(self.relogio.agora());
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
        let agora_s = self.relogio.agora();
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

        let visto = self.relogio.agora();
        self.estado.guardar_sessao(cert_key.clone(), novo_token, visto);
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

/// Hex de um buffer, para o log seguro da canônica (só o hash, nunca o texto,
/// que no tokensessao contém PIN e OTP).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
