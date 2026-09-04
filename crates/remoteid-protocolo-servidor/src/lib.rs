//! Protocolo do servidor RemoteID (Certisign): o contrato IMUTÁVEL.
//!
//! Este domínio não está sob nosso controle. Paridade byte a byte com o app
//! oficial de macOS: os corpos das requisições ([`protocol`]), os endpoints e a
//! classificação de erros ([`config`]), e a canonicalização que autentica cada
//! requisição ([`canonical`]). Reserializar um corpo ou mudar a ordem da
//! canônica quebra a assinatura do `Bearer`. Mudanças aqui só quando o servidor
//! muda, e cobertas por testes de ouro.

pub mod canonical;
pub mod config;
pub mod protocol;
pub mod resposta;
