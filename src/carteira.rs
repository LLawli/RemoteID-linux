//! O que a janela mostra da conta e da carteira, montado do estado. Fica sem
//! GTK para ser testado: a janela só desenha o que [`montar`] devolve e
//! compara com o anterior para saber se precisa redesenhar.

use crate::cripto::de_b64;
use crate::estado::{Estado, TTL_SESSAO_S};
use crate::x509;

/// A partir de quantos dias para vencer o cartão avisa.
pub const DIAS_ALERTA: i64 = 30;

const DIA_S: u64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Documento {
    Cpf(String),
    Cnpj(String),
}

impl Documento {
    /// O documento do CN `NOME:DOCUMENTO` da ICP-Brasil, só com os dígitos.
    fn do_titular(documento: &str) -> Option<Documento> {
        if !documento.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        match documento.len() {
            11 => Some(Documento::Cpf(documento.into())),
            14 => Some(Documento::Cnpj(documento.into())),
            _ => None,
        }
    }

    /// `e-CPF` ou `e-CNPJ`, como a ICP-Brasil chama o certificado.
    pub fn tipo(&self) -> &'static str {
        match self {
            Documento::Cpf(_) => "e-CPF",
            Documento::Cnpj(_) => "e-CNPJ",
        }
    }

    /// `CPF 000.000.000-00` ou `CNPJ 00.000.000/0000-00`.
    pub fn formatado(&self) -> String {
        match self {
            Documento::Cpf(d) => format!("CPF {}.{}.{}-{}", &d[..3], &d[3..6], &d[6..9], &d[9..]),
            Documento::Cnpj(d) => format!(
                "CNPJ {}.{}.{}/{}-{}",
                &d[..2],
                &d[2..5],
                &d[5..8],
                &d[8..12],
                &d[12..]
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sessao {
    /// A próxima assinatura usa a sessão em cache. `ate` é quando ela vence,
    /// se dá para saber.
    Aberta { ate: Option<u64> },
    /// A próxima assinatura pede PIN e OTP.
    Fechada,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cartao {
    /// A [`crate::protocolo::Certificado::chave`], que a janela devolve ao
    /// escolher este cartão.
    pub chave: String,
    /// O nome do titular, sem o documento; o número de série quando a
    /// carteira não trouxe o certificado.
    pub nome: String,
    pub documento: Option<Documento>,
    /// O `CN` da AC emissora, ou o emissor do `keyName`.
    pub emissor: String,
    pub serie: String,
    /// O fim da validade, em segundos desde 1970.
    pub validade: Option<u64>,
    pub ativo: bool,
    pub sessao: Sessao,
    /// Os nomes das autoridades acima do certificado, do emissor até a raiz.
    pub autoridades: Vec<String>,
}

impl Cartao {
    /// Dias inteiros até vencer; negativo depois de vencido.
    pub fn dias_restantes(&self, agora: u64) -> Option<i64> {
        let validade = self.validade?;
        let dias = validade.abs_diff(agora) / DIA_S;
        Some(if validade >= agora {
            dias as i64
        } else {
            -(dias as i64) - 1
        })
    }

    /// Os dias, quando já é hora de avisar.
    pub fn alerta(&self, agora: u64) -> Option<i64> {
        self.dias_restantes(agora).filter(|d| *d <= DIAS_ALERTA)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carteira {
    pub nome: Option<String>,
    pub email: Option<String>,
    pub computador: Option<String>,
    pub cartoes: Vec<Cartao>,
}

impl Carteira {
    pub fn ativo(&self) -> Option<usize> {
        self.cartoes.iter().position(|c| c.ativo)
    }
}

/// O nome e o documento do `CN` da ICP-Brasil (`NOME:DOCUMENTO`). Um `CN` sem
/// documento é só o nome.
pub fn titular(cn: &str) -> (String, Option<Documento>) {
    match cn.split_once(':') {
        Some((nome, documento)) => (nome.to_string(), Documento::do_titular(documento)),
        None => (cn.to_string(), None),
    }
}

/// A carteira como a janela a mostra, ou `None` quando a conta ainda não está
/// pronta (falta entrar, registrar ou baixar a carteira).
pub fn montar(estado: &Estado, agora: u64) -> Option<Carteira> {
    if !estado.preparado() {
        return None;
    }
    let ativo = estado.certificado().map(|c| c.chave());
    let cartoes = estado
        .certificados
        .iter()
        .map(|c| {
            let chave = c.chave();
            let campos = c
                .base64
                .as_deref()
                .and_then(de_b64)
                .and_then(|der| x509::ler(&der).ok());
            let (nome, documento) = match campos.as_ref().and_then(|f| f.nome.as_deref()) {
                Some(cn) => titular(cn),
                None => (c.serial_number.clone(), None),
            };
            let sessao = match estado.sessao(&chave, agora, TTL_SESSAO_S) {
                Some(s) => Sessao::Aberta {
                    ate: s.ate(agora, TTL_SESSAO_S),
                },
                None => Sessao::Fechada,
            };
            Cartao {
                ativo: ativo.as_deref() == Some(chave.as_str()),
                nome,
                documento,
                emissor: campos
                    .as_ref()
                    .and_then(|f| f.emissor.clone())
                    .unwrap_or_else(|| c.issue.clone()),
                serie: c.serial_number.clone(),
                validade: campos.as_ref().map(|f| f.validade),
                sessao,
                autoridades: c
                    .cadeia
                    .iter()
                    .filter_map(|b| x509::ler(&de_b64(b)?).ok()?.nome)
                    .collect(),
                chave,
            }
        })
        .collect();
    Some(Carteira {
        nome: estado.nome.clone(),
        email: estado.email.clone(),
        computador: estado.nome_desktop.clone(),
        cartoes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cadeia::certificados_do_pacote;
    use crate::cripto::b64;
    use crate::protocolo::Certificado;

    const FINAL: &[u8] = include_bytes!("../tests/mock/fake-cert.der");
    const PACOTE: &[u8] = include_bytes!("../tests/mock/AC_TESTE_DESKTOPID.p7c");
    /// O `notAfter` do certificado de teste: 2036-08-31 19:17:34 UTC.
    const VALIDADE: u64 = 2_103_823_054;
    const AGORA: u64 = 1_800_000_000;

    fn estado() -> Estado {
        let mut titular = Certificado::do_key_name("5A3F;AC TESTE", Some(b64(FINAL))).unwrap();
        titular.cadeia = certificados_do_pacote(PACOTE)
            .unwrap()
            .iter()
            .map(|der| b64(der))
            .collect();
        let empresa = Certificado::do_key_name("7C11;AC OUTRA", None).unwrap();
        Estado {
            nome: Some("TESTE DESKTOPID".into()),
            email: Some("teste@remoteid.local".into()),
            codigo_desktop: Some("codigo".into()),
            nome_desktop: Some("fedora".into()),
            certificados: vec![titular, empresa],
            ..Estado::default()
        }
    }

    #[test]
    fn sem_conta_pronta_nao_ha_carteira() {
        assert_eq!(montar(&Estado::default(), AGORA), None);
        let sem_registro = Estado {
            codigo_desktop: None,
            ..estado()
        };
        assert_eq!(montar(&sem_registro, AGORA), None);
    }

    #[test]
    fn o_cartao_sai_do_certificado() {
        let carteira = montar(&estado(), AGORA).unwrap();
        assert_eq!(carteira.computador.as_deref(), Some("fedora"));
        let c = &carteira.cartoes[0];
        assert_eq!(c.nome, "TESTE DESKTOPID");
        assert_eq!(c.documento, Some(Documento::Cpf("00000000000".into())));
        assert_eq!(c.emissor, "AC TESTE DESKTOPID");
        assert_eq!(c.serie, "5A3F");
        assert_eq!(c.validade, Some(VALIDADE));
        assert!(c.ativo, "sem escolha, o primeiro assina");
        assert_eq!(c.autoridades.len(), 2);
        assert!(
            c.autoridades
                .contains(&"AC RAIZ TESTE DESKTOPID".to_string())
        );
    }

    #[test]
    fn sem_o_der_o_cartao_mostra_o_que_a_carteira_tem() {
        let c = &montar(&estado(), AGORA).unwrap().cartoes[1];
        assert_eq!(c.nome, "7C11");
        assert_eq!(c.documento, None);
        assert_eq!(c.emissor, "AC OUTRA");
        assert_eq!(c.validade, None);
        assert_eq!(c.alerta(AGORA), None);
        assert!(!c.ativo);
    }

    #[test]
    fn a_escolha_e_a_sessao_seguem_o_estado() {
        let mut e = estado();
        e.certificado_ativo = Some("7C11;AC OUTRA".into());
        let token = format!("sessaoAssinatura;1;AC;7C11;0;jwt;{};hmac", AGORA - 60);
        e.guardar_sessao("7C11;AC OUTRA".into(), token, AGORA - 60);
        let carteira = montar(&e, AGORA).unwrap();
        assert_eq!(carteira.ativo(), Some(1));
        assert_eq!(carteira.cartoes[0].sessao, Sessao::Fechada);
        assert_eq!(
            carteira.cartoes[1].sessao,
            Sessao::Aberta {
                ate: Some(AGORA - 60 + TTL_SESSAO_S)
            }
        );
        // Vencida, a sessão some sem ninguém gravar nada.
        let depois = montar(&e, AGORA + TTL_SESSAO_S).unwrap();
        assert_eq!(depois.cartoes[1].sessao, Sessao::Fechada);
    }

    #[test]
    fn os_dias_contam_inteiros_e_o_alerta_so_perto_do_fim() {
        let c = &montar(&estado(), AGORA).unwrap().cartoes[0];
        assert_eq!(c.dias_restantes(VALIDADE), Some(0));
        assert_eq!(c.dias_restantes(VALIDADE - DIA_S), Some(1));
        assert_eq!(c.dias_restantes(VALIDADE + 1), Some(-1));
        assert_eq!(c.alerta(VALIDADE - 31 * DIA_S), None);
        assert_eq!(c.alerta(VALIDADE - 30 * DIA_S), Some(30));
        assert_eq!(c.alerta(VALIDADE + 1), Some(-1));
    }

    #[test]
    fn documentos_da_icp_brasil() {
        let cpf = Documento::do_titular("12345678909").unwrap();
        assert_eq!(
            (cpf.tipo(), cpf.formatado().as_str()),
            ("e-CPF", "CPF 123.456.789-09")
        );
        let cnpj = Documento::do_titular("12345678000190").unwrap();
        assert_eq!(
            (cnpj.tipo(), cnpj.formatado().as_str()),
            ("e-CNPJ", "CNPJ 12.345.678/0001-90")
        );
        assert_eq!(Documento::do_titular("123"), None);
        assert_eq!(Documento::do_titular("1234567890a"), None);
        assert_eq!(
            titular("FULANO:12345678909"),
            ("FULANO".into(), Some(Documento::Cpf("12345678909".into())))
        );
        assert_eq!(titular("SEM DOCUMENTO"), ("SEM DOCUMENTO".into(), None));
    }
}
