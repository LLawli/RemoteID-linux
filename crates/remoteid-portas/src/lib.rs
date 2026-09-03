//! As portas do RemoteID-linux: os contratos entre o núcleo e a borda de I/O.
//!
//! Cada trait aqui é implementada por um ou mais adaptadores (os crates
//! `remoteid-store-json`, `remoteid-chave-pem`, `remoteid-http`,
//! `remoteid-diag-jsonl`, ...). O núcleo/aplicação depende só destas traits,
//! nunca de uma implementação, então trocar onde os dados moram (`.json` ->
//! `.xml` -> Postgres) ou onde a chave vive (`.pem` -> Postgres/HSM) é escrever
//! um novo adaptador, sem tocar no núcleo.
//!
//! Duas regras de projeto que valem para todas as portas:
//!
//! - **A chave privada nunca sai do cofre.** [`CofreDeChave`] expõe `assinar`,
//!   nunca a chave crua. É o que viabiliza um adaptador Postgres/HSM.
//! - **Estado e chave são endereçados por [`IdInstalacao`]**, não por uma
//!   instalação global única, para a versão central multi-conta cair fora sem
//!   mudança quebradora.

use serde_json::Value;

use remoteid_autorizacao::Fatores;
use remoteid_estado::Estado;
use remoteid_tipos::{IdInstalacao, Result};

/// Onde o [`Estado`] (dados da conta) é lido e gravado.
///
/// Adaptador padrão: `remoteid-store-json` (`state.json`). Trocáveis: XML,
/// Postgres. O `id` endereça a conta.
pub trait RepositorioEstado: Send + Sync {
    fn carregar(&self, id: &IdInstalacao) -> Result<Estado>;
    fn salvar(&self, id: &IdInstalacao, estado: &Estado) -> Result<()>;
    /// Apaga o estado da instalação (o "reinstalar"). Ausência não é erro.
    fn apagar(&self, id: &IdInstalacao) -> Result<()>;
}

/// A chave da instalação: assina SEM nunca expor o material privado.
///
/// Adaptador padrão: `remoteid-chave-pem` (`installation-key.pem`). Trocáveis:
/// Postgres, HSM. Um cofre pode gerar a chave na primeira vez (o desktop) ou
/// exigir que ela já exista (um HSM).
pub trait CofreDeChave: Send + Sync {
    /// A chave pública em PEM completo, para o registro no servidor.
    fn publica_pem(&self, id: &IdInstalacao) -> Result<String>;
    /// Assina um digest SHA-256 (RSA PKCS#1 v1.5), 256 bytes para RSA-2048.
    fn assinar_digest(&self, id: &IdInstalacao, digest: &[u8]) -> Result<Vec<u8>>;
    /// PKCS#1 v1.5 CRU (sem DigestInfo): o contrato do `CKM_RSA_PKCS` do PKCS#11.
    fn assinar_pkcs1_v15_cru(&self, id: &IdInstalacao, dados: &[u8]) -> Result<Vec<u8>>;
    /// O valor do header `Authorization: Bearer`: base64(assinar(SHA256(canonical))).
    fn bearer_assinado(&self, id: &IdInstalacao, canonical: &str) -> Result<String>;
}

/// Requisição HTTP já pronta para enviar (corpo serializado, Bearer calculado).
///
/// O corpo vai como [`Value`] mas o transporte deve enviá-lo com os MESMOS bytes
/// que a assinatura do Bearer cobre: reserializar mudaria os bytes e a
/// assinatura deixaria de bater (ver o protocolo do servidor).
pub struct RequisicaoHttp {
    pub metodo: String,
    pub url: String,
    pub corpo: Option<Value>,
    pub bearer: Option<String>,
    /// Nome do passo do protocolo ("carteira", "tokensessao"), para o diag.
    pub rotulo: String,
}

/// Resposta crua do servidor. A interpretação ("HTTP 200 pode ser erro", a
/// classificação da mensagem) é do domínio do protocolo, não do transporte.
pub struct RespostaHttp {
    pub status: u16,
    pub corpo: String,
}

/// O transporte até o servidor RemoteID. Adaptador padrão: `remoteid-http` (ureq).
pub trait TransporteRemoteId: Send + Sync {
    fn requisitar(&self, req: &RequisicaoHttp) -> Result<RespostaHttp>;
}

/// O log de diagnóstico. Adaptador padrão: `remoteid-diag-jsonl`.
///
/// O adaptador é responsável por aplicar a redação de segredos (a LÓGICA de
/// redação é pura e testável no núcleo; o sink só a aplica e persiste). Assim a
/// garantia "PIN/OTP nunca vazam" não depende de o chamador lembrar de redigir.
pub trait Diagnostico: Send + Sync {
    fn evento(&self, tipo: &str, campos: Value);
    /// Caminho do arquivo desta execução, para o CLI mostrar num erro.
    fn caminho(&self) -> Option<std::path::PathBuf>;
}

/// O relógio, para o núcleo ser determinístico e testável (o pré-filtro do cache
/// do sessionToken usa o tempo). Adaptador padrão: o relógio do sistema.
pub trait Relogio: Send + Sync {
    /// Epoch em segundos.
    fn agora(&self) -> u64;
}

/// Fatos do ambiente que o protocolo precisa e que não são armazenamento:
/// o hostname (`dominioRede`, que o servidor recusa vazio) e o usuário local
/// (`nomeUsuarioLocal`). Adaptador padrão: o sistema real.
pub trait Ambiente: Send + Sync {
    fn hostname(&self) -> String;
    fn usuario_local(&self) -> String;
}

/// O que a UI precisa saber para escrever um diálogo de PIN/OTP útil.
#[derive(Debug, Clone, Default)]
pub struct Contexto {
    /// Nome bruto do hospedeiro (`comm` do processo cliente), quando conhecido.
    pub hospedeiro: Option<String>,
    /// Common Name do certificado ativo, a UI mostra "Assinar como <CN>".
    pub titular: Option<String>,
}

/// Como o serviço obtém PIN e OTP quando o cache de sessão não basta.
///
/// Um método só porque o `tokensessao` exige os DOIS fatores no mesmo request.
/// Adaptadores: o diálogo GTK4 (produção) e fatores fixos (teste). Nenhum lê
/// PIN/OTP de ambiente ou arquivo: só interação humana ou injeção em teste.
pub trait Prompter: Send + Sync {
    /// Devolve [`Fatores::PinOtp`] se aprovado, ou `Err(Error::Uso("cancelado ..."))`
    /// se o usuário fechou o diálogo.
    fn pedir_pin_otp(&self, contexto: &Contexto) -> Result<Fatores>;
}
