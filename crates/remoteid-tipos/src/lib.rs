//! Erros do motor, com a origem do problema explícita.
//!
//! A distinção que importa na prática (e que o harness em Python já fazia) é
//! DE QUEM é o problema: do dado que o usuário digitou, do payload que este
//! cliente monta, ou do backend da Certisign. Sem isso o usuário perde tempo
//! conferindo credencial quando o defeito é do CLI, e vice-versa.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Identidade de uma instalação/conta.
///
/// Existe para que as portas de estado e de chave sejam endereçadas por conta,
/// não por uma instalação global única. No desktop é um singleton
/// ([`IdInstalacao::local`]); numa futura versão central em Postgres endereça
/// cada conta guardada. Desenhar assim desde já evita uma mudança quebradora
/// quando essa versão existir.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdInstalacao(pub String);

impl IdInstalacao {
    /// A instalação única desta máquina (o caso desktop).
    pub fn local() -> Self {
        IdInstalacao("local".into())
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

impl Default for IdInstalacao {
    fn default() -> Self {
        IdInstalacao::local()
    }
}

impl fmt::Display for IdInstalacao {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// De quem é a culpa por uma resposta de erro do backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origem {
    /// Dado que o usuário corrige: credencial, PIN, OTP, domínio.
    Usuario,
    /// O payload que ESTE cliente monta está errado (campo/formato).
    Cliente,
    /// Infra/backend da Certisign: não adianta mexer no payload nem na conta.
    Servidor,
    /// Mensagem não reconhecida.
    Desconhecida,
}

impl fmt::Display for Origem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Origem::Usuario => "erro de dado seu",
            Origem::Cliente => "erro do cliente",
            Origem::Servidor => "erro do servidor",
            Origem::Desconhecida => "origem desconhecida",
        })
    }
}

/// Erro de negócio devolvido pelo backend.
///
/// O backend responde **HTTP 200 mesmo em erro**, com `{"status": false,
/// "message": "..."}`. Quem só olha o código HTTP conclui que deu certo.
#[derive(Debug, Clone)]
pub struct ServerError {
    pub http_status: u16,
    pub message: String,
    pub origem: Origem,
    /// Explicação em português para o usuário, quando a mensagem é conhecida.
    pub hint: Option<&'static str>,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (HTTP {}", self.message, self.http_status)?;
        if self.origem != Origem::Desconhecida {
            write!(f, ", {}", self.origem)?;
        }
        write!(f, ")")?;
        if let Some(h) = self.hint {
            write!(f, " — {h}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("erro de E/S: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON inválido: {0}")]
    Json(#[from] serde_json::Error),

    #[error("falha de rede: {0}")]
    Rede(String),

    #[error("resposta não era JSON (HTTP {status}): {trecho}")]
    RespostaNaoJson { status: u16, trecho: String },

    #[error("{0}")]
    Servidor(ServerError),

    #[error("erro de criptografia: {0}")]
    Cripto(String),

    #[error("estado local: {0}")]
    Estado(String),

    #[error("{0}")]
    Uso(String),
}

impl Error {
    pub fn cripto(msg: impl Into<String>) -> Self {
        Error::Cripto(msg.into())
    }
    pub fn estado(msg: impl Into<String>) -> Self {
        Error::Estado(msg.into())
    }
    pub fn uso(msg: impl Into<String>) -> Self {
        Error::Uso(msg.into())
    }

    /// A origem do problema, para o CLI decidir o que dizer ao usuário.
    pub fn origem(&self) -> Origem {
        match self {
            Error::Servidor(e) => e.origem,
            Error::Rede(_) => Origem::Servidor,
            Error::Uso(_) => Origem::Usuario,
            // Estado local ("ainda não registrado") não é dado errado do
            // usuário: a própria mensagem já diz qual comando falta rodar, e
            // rotulá-la de "confira a credencial" manda investigar o lugar errado.
            _ => Origem::Desconhecida,
        }
    }
}
