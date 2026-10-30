//! O que persiste entre execuções: a conta, o registro desta máquina, a
//! carteira e as sessões de assinatura em cache.
//!
//! Fica num JSON 0600 no diretório do RemoteID ([`crate::caminhos`]), gravado
//! por troca atômica: o módulo PKCS#11 e a janela leem o mesmo arquivo, e uma
//! escrita pela metade não pode deixar nenhum dos dois sem conta.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::protocolo::Certificado;

/// Por quanto tempo uma sessão em cache vale a tentativa, quando o relógio é
/// confiável. É um palpite: o servidor nunca disse a validade, e é ele quem
/// decide. Errar para mais custa uma requisição recusada; para menos, um OTP.
pub const TTL_SESSAO_S: u64 = 15 * 60;

/// Diferença entre o relógio local e o do token acima da qual o pré-filtro
/// desiste de julgar e deixa o servidor decidir.
const DRIFT_MAXIMO_S: u64 = 24 * 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Estado {
    pub user_id: Option<i64>,
    pub organizacao_id: Option<i64>,
    pub nome: Option<String>,
    pub cpf: Option<String>,
    pub email: Option<String>,
    pub codigo_desktop: Option<String>,
    pub nome_desktop: Option<String>,
    /// Se a conta tem celular pareado para aprovação. Só informa: quem decide
    /// o caminho de assinatura é este cliente, e hoje ele é PIN e OTP.
    pub celular_pareado: Option<bool>,
    pub certificados: Vec<Certificado>,
    /// A [`Certificado::chave`] do certificado escolhido para assinar.
    pub certificado_ativo: Option<String>,
    /// As sessões abertas, pela [`Certificado::chave`].
    pub sessoes: BTreeMap<String, Sessao>,
}

/// Um `sessionToken` em cache. Autoriza assinaturas: só vive no estado 0600 e
/// nunca vai em claro para o diagnóstico.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sessao {
    pub token: String,
    /// Quando o servidor diz que emitiu (o penúltimo campo do token).
    pub emitido_em: Option<u64>,
    /// Quando guardamos, pelo relógio local.
    pub visto_em: u64,
}

/// O instante de emissão que o servidor põe no token:
/// `sessaoAssinatura;<userId>;<emissor>;<serial>;0;<jwt>;<epoch>;<hmac>`.
/// O token continua opaco; sem o campo, o pré-filtro só não opina.
pub fn epoch_do_token(token: &str) -> Option<u64> {
    let campos: Vec<&str> = token.split(';').collect();
    let penultimo = campos.len().checked_sub(2)?;
    campos[penultimo].parse().ok()
}

impl Sessao {
    pub fn nova(token: String, agora: u64) -> Sessao {
        Sessao {
            emitido_em: epoch_do_token(&token),
            token,
            visto_em: agora,
        }
    }

    /// Se vale tentar assinar com esta sessão antes de pedir PIN e OTP. Sem a
    /// data de emissão, ou com o relógio local muito longe do de quando a
    /// guardamos, tenta: o servidor decide.
    pub fn vale_tentar(&self, agora: u64, ttl: u64) -> bool {
        let Some(emitido) = self.emitido_em else {
            return true;
        };
        if agora.abs_diff(self.visto_em) > DRIFT_MAXIMO_S {
            return true;
        }
        agora.saturating_sub(emitido) < ttl
    }
}

impl Estado {
    /// Lê o estado; um arquivo que ainda não existe é uma instalação nova.
    pub fn carregar(caminho: &Path) -> io::Result<Estado> {
        match fs::read(caminho) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Estado::default()),
            Err(e) => Err(e),
        }
    }

    pub fn salvar(&self, caminho: &Path) -> io::Result<()> {
        let texto = serde_json::to_vec_pretty(self).expect("o estado sempre vira JSON");
        gravar_privado(caminho, &texto)
    }

    pub fn preparado(&self) -> bool {
        self.codigo_desktop.is_some() && !self.certificados.is_empty()
    }

    /// O certificado de assinatura: o escolhido, ou o primeiro da carteira se
    /// a escolha não estiver mais nela.
    pub fn certificado(&self) -> Option<&Certificado> {
        let escolhido = self.certificado_ativo.as_deref().and_then(|chave| {
            self.certificados
                .iter()
                .find(|c| c.chave() == chave || c.key_name == chave)
        });
        escolhido.or(self.certificados.first())
    }

    /// A sessão em cache do certificado, se vale tentar com ela.
    pub fn sessao(&self, chave: &str, agora: u64, ttl: u64) -> Option<&Sessao> {
        self.sessoes
            .get(chave)
            .filter(|s| s.vale_tentar(agora, ttl))
    }

    pub fn guardar_sessao(&mut self, chave: String, token: String, agora: u64) {
        self.sessoes.insert(chave, Sessao::nova(token, agora));
    }

    pub fn esquecer_sessao(&mut self, chave: &str) {
        self.sessoes.remove(chave);
    }
}

/// Grava `conteudo` com permissão 0600, por troca atômica: escreve num
/// arquivo ao lado e renomeia por cima.
pub fn gravar_privado(caminho: &Path, conteudo: &[u8]) -> io::Result<()> {
    if let Some(pai) = caminho.parent() {
        fs::create_dir_all(pai)?;
    }
    let temporario = caminho.with_extension(format!("tmp-{}", std::process::id()));
    let mut arquivo = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporario)?;
    arquivo.write_all(conteudo)?;
    arquivo.sync_all()?;
    fs::rename(&temporario, caminho)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_epoch_e_o_penultimo_campo() {
        let token = "sessaoAssinatura;327989;CN%3DAC;SN;0;ZXlK;1788393921;hmac=";
        assert_eq!(epoch_do_token(token), Some(1_788_393_921));
        assert_eq!(epoch_do_token("opaco"), None);
        assert_eq!(epoch_do_token("a;b;c"), None);
        assert_eq!(epoch_do_token(""), None);
    }

    #[test]
    fn o_prefiltro_so_recusa_quando_tem_certeza() {
        let s = Sessao {
            token: "t".into(),
            emitido_em: Some(1000),
            visto_em: 1000,
        };
        assert!(s.vale_tentar(1000 + TTL_SESSAO_S - 1, TTL_SESSAO_S));
        assert!(!s.vale_tentar(1000 + TTL_SESSAO_S, TTL_SESSAO_S));
        // Relógio local fora de controle: o servidor decide.
        assert!(s.vale_tentar(1000 + DRIFT_MAXIMO_S + 1, TTL_SESSAO_S));
        // Sem data de emissão no token: idem.
        let opaca = Sessao {
            emitido_em: None,
            ..s
        };
        assert!(opaca.vale_tentar(u64::MAX, TTL_SESSAO_S));
    }

    #[test]
    fn a_escolha_que_saiu_da_carteira_cai_no_primeiro() {
        let a = Certificado::do_key_name("A;X", None).unwrap();
        let b = Certificado::do_key_name("B;Y", None).unwrap();
        let mut e = Estado {
            certificados: vec![a.clone(), b.clone()],
            ..Estado::default()
        };
        assert_eq!(e.certificado(), Some(&a));
        e.certificado_ativo = Some(b.chave());
        assert_eq!(e.certificado(), Some(&b));
        e.certificado_ativo = Some("C;Z".into());
        assert_eq!(e.certificado(), Some(&a));
    }
}
