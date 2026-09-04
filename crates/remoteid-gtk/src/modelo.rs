//! Modelos de dados para as telas da interface GTK4.
//!
//! Desacoplados da persistência direta e do transporte. A aplicação converte
//! as respostas do serviço/protocolo para estes modelos, e o modo `--preview`
//! preenche com dados mock para validação visual.

use remoteid_protocolo::SucessoResposta;

/// Um certificado resumido para exibição nas telas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificado {
    /// Nome do titular (ex.: "MARIA SILVA:12345678900").
    pub titular: String,
    /// Emissor (Autoridade Certificadora), legível.
    pub emissor: String,
    /// Número de série do certificado.
    pub serial: String,
    /// Identificador técnico no protocolo (`<serial>;<issuer DN>`).
    pub key_name: String,
    /// Unidades Organizacionais (OU) do certificado.
    pub ous: Vec<String>,
    /// Data de validade (expiração) no formato DD/MM/AAAA, se disponível.
    pub validade: Option<String>,
}

/// Sessão de assinatura em cache para um certificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sessao {
    pub cert_key: String,
    /// Epoch em segundos da emissão do token (se presente).
    pub emitido_em: Option<u64>,
    /// Epoch em segundos da última utilização/validação local.
    pub visto_em: u64,
}

/// Estado do aplicativo exibido no painel inicial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstadoApp {
    /// Se a instalação foi preparada (login + registro + carteira).
    pub preparado: bool,
    pub titular: Option<String>,
    pub codigo_desktop: Option<String>,
    pub certificados: Vec<Certificado>,
    /// `key_name` do certificado escolhido como padrão.
    pub certificado_ativo: Option<String>,
    pub sessoes: Vec<Sessao>,
}

impl EstadoApp {
    /// Retorna o certificado ativo no momento (ou o primeiro disponível).
    pub fn certificado_ativo_ou_primeiro(&self) -> Option<&Certificado> {
        if let Some(chave) = &self.certificado_ativo {
            if let Some(c) = self.certificados.iter().find(|c| &c.key_name == chave) {
                return Some(c);
            }
        }
        self.certificados.first()
    }

    /// Converte um `SucessoResposta::Status` do protocolo em `EstadoApp`.
    pub fn de_status(resp: &SucessoResposta) -> Option<Self> {
        match resp {
            SucessoResposta::Status {
                preparado,
                codigo_desktop,
                titular,
                certificados,
                certificado_ativo,
                sessoes,
                ..
            } => {
                let titular_str = titular.clone().unwrap_or_else(|| "Titular".to_string());
                let certs = certificados
                    .iter()
                    .map(|c| {
                        let emissor = extrair_cn(&c.issue).unwrap_or_else(|| c.issue.clone());
                        Certificado {
                            titular: titular_str.clone(),
                            emissor,
                            serial: c.serial_number.clone(),
                            key_name: c.key_name.clone(),
                            ous: c.ous.clone(),
                            validade: c.validade.clone(),
                        }
                    })
                    .collect();

                let sess = sessoes
                    .iter()
                    .map(|s| Sessao {
                        cert_key: s.cert_key.clone(),
                        emitido_em: s.emitido_em,
                        visto_em: s.visto_em,
                    })
                    .collect();

                Some(EstadoApp {
                    preparado: *preparado,
                    titular: titular.clone(),
                    codigo_desktop: codigo_desktop.clone(),
                    certificados: certs,
                    certificado_ativo: certificado_ativo.clone(),
                    sessoes: sess,
                })
            }
            _ => None,
        }
    }

    /// Mock para `--preview`: instalação preparada com 1 certificado e sessão cacheada.
    pub fn mock_preparado() -> Self {
        EstadoApp {
            preparado: true,
            titular: Some("MARIA SILVA:12345678900".to_string()),
            codigo_desktop: Some("8f3a1c2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b".to_string()),
            certificados: vec![Certificado {
                titular: "MARIA SILVA:12345678900".to_string(),
                emissor: "AC OAB G3".to_string(),
                serial: "3A:1F:9C:22:04:8B".to_string(),
                key_name: "3A1F9C22048B;CN=AC OAB G3,O=ICP-Brasil,C=BR".to_string(),
                ous: vec![
                    "Autenticado por Certisign".to_string(),
                    "Assinatura Tipo A3".to_string(),
                    "Advogado".to_string(),
                ],
                validade: Some("14/09/2027".to_string()),
            }],
            certificado_ativo: Some("3A1F9C22048B;CN=AC OAB G3,O=ICP-Brasil,C=BR".to_string()),
            sessoes: vec![Sessao {
                cert_key: "3A1F9C22048B;CN=AC OAB G3,O=ICP-Brasil,C=BR".to_string(),
                emitido_em: Some(1_756_900_000),
                visto_em: 1_756_900_600,
            }],
        }
    }

    /// Mock para `--preview`: recém-instalado, ainda não preparado (tela de login).
    pub fn mock_nao_preparado() -> Self {
        EstadoApp {
            preparado: false,
            titular: None,
            codigo_desktop: None,
            certificados: Vec::new(),
            certificado_ativo: None,
            sessoes: Vec::new(),
        }
    }

    /// Mock para `--preview`: carteira com múltiplos certificados.
    pub fn mock_multi_token() -> Self {
        EstadoApp {
            preparado: true,
            titular: Some("MARIA SILVA:12345678900".to_string()),
            codigo_desktop: Some("8f3a1c2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b".to_string()),
            certificados: vec![
                Certificado {
                    titular: "MARIA SILVA:12345678900".to_string(),
                    emissor: "AC OAB G3".to_string(),
                    serial: "3A:1F:9C:22:04:8B".to_string(),
                    key_name: "3A1F9C22048B;CN=AC OAB G3".to_string(),
                    ous: vec![
                        "Autenticado por Certisign".to_string(),
                        "Assinatura Tipo A3".to_string(),
                        "Advogado".to_string(),
                    ],
                    validade: Some("14/09/2027".to_string()),
                },
                Certificado {
                    titular: "MARIA SILVA:12345678900".to_string(),
                    emissor: "AC Certisign RFB G5".to_string(),
                    serial: "7C:88:1E:0A:D3:44".to_string(),
                    key_name: "7C881E0AD344;CN=AC Certisign RFB G5".to_string(),
                    ous: vec![
                        "Secretaria da Receita Federal do Brasil - RFB".to_string(),
                        "AR SERPRO".to_string(),
                    ],
                    validade: Some("02/03/2026".to_string()),
                },
            ],
            certificado_ativo: Some("3A1F9C22048B;CN=AC OAB G3".to_string()),
            sessoes: Vec::new(),
        }
    }
}

/// Parâmetros de configuração da aplicação.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigApp {
    /// Duração do cache do PIN em memória (minutos; 0 desativa).
    pub cache_pin_min: u32,
    /// TTL hipotético da sessão no pré-filtro (minutos).
    pub ttl_sessao_min: u32,
    /// Nome da aplicação reportado ao servidor.
    pub nome_aplicacao: String,
    /// Caminho da pasta de diagnósticos / logs.
    pub caminho_log: String,
}

impl ConfigApp {
    pub fn mock() -> Self {
        ConfigApp {
            cache_pin_min: 5,
            ttl_sessao_min: 15,
            nome_aplicacao: "RemoteID-linux".to_string(),
            caminho_log: "~/.local/state/remoteid/diag".to_string(),
        }
    }
}

impl Certificado {
    /// Separa o nome do titular e o documento formatado (CPF/CNPJ).
    pub fn nome_e_documento(&self) -> (String, Option<String>) {
        separar_nome_e_documento(&self.titular)
    }
}

impl EstadoApp {
    /// Retorna nome e documento formatado do titular da instalação.
    pub fn nome_e_documento_titular(&self) -> (String, Option<String>) {
        match &self.titular {
            Some(t) => separar_nome_e_documento(t),
            None => ("Não identificado".to_string(), None),
        }
    }
}

/// Formata um número de documento brasileiro (CPF com 11 dígitos ou CNPJ com 14 dígitos).
pub fn formatar_documento(doc: &str) -> String {
    let limpo: String = doc.chars().filter(|c| c.is_ascii_digit()).collect();
    if limpo.len() == 11 {
        format!(
            "CPF {}.{}.{}-{}",
            &limpo[0..3],
            &limpo[3..6],
            &limpo[6..9],
            &limpo[9..11]
        )
    } else if limpo.len() == 14 {
        format!(
            "CNPJ {}.{}.{}/{}-{}",
            &limpo[0..2],
            &limpo[2..5],
            &limpo[5..8],
            &limpo[8..12],
            &limpo[12..14]
        )
    } else if !doc.trim().is_empty() {
        format!("Doc. {}", doc.trim())
    } else {
        String::new()
    }
}

/// Separa o nome do titular e o documento a partir do padrão ICP-Brasil (ex.: "NOME:12345678900").
pub fn separar_nome_e_documento(titular: &str) -> (String, Option<String>) {
    if let Some((nome, doc)) = titular.split_once(':') {
        let nome = nome.trim();
        let doc_fmt = formatar_documento(doc);
        let doc_opt = if doc_fmt.is_empty() {
            None
        } else {
            Some(doc_fmt)
        };
        (nome.to_string(), doc_opt)
    } else {
        (titular.trim().to_string(), None)
    }
}

/// Extrai o valor do CN de uma string de DN (Distinguished Name).
fn extrair_cn(dn: &str) -> Option<String> {
    for parte in dn.split(',') {
        let parte = parte.trim();
        if let Some(valor) = parte.strip_prefix("CN=") {
            return Some(valor.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrai_cn_corretamente() {
        let dn = "CN=AC OAB G3, O=ICP-Brasil, C=BR";
        assert_eq!(extrair_cn(dn), Some("AC OAB G3".to_string()));
    }

    #[test]
    fn certificado_ativo_seleciona_correto() {
        let mock = EstadoApp::mock_multi_token();
        let ativo = mock.certificado_ativo_ou_primeiro().unwrap();
        assert_eq!(ativo.emissor, "AC OAB G3");
    }

    #[test]
    fn separa_cpf_corretamente() {
        let (nome, doc) = separar_nome_e_documento("MARIA SILVA:12345678900");
        assert_eq!(nome, "MARIA SILVA");
        assert_eq!(doc, Some("CPF 123.456.789-00".to_string()));
    }

    #[test]
    fn separa_cnpj_corretamente() {
        let (nome, doc) = separar_nome_e_documento("EMPRESA TESTE LTDA:12345678000195");
        assert_eq!(nome, "EMPRESA TESTE LTDA");
        assert_eq!(doc, Some("CNPJ 12.345.678/0001-95".to_string()));
    }

    #[test]
    fn titular_sem_documento_mantem_nome() {
        let (nome, doc) = separar_nome_e_documento("JOAO DA SILVA");
        assert_eq!(nome, "JOAO DA SILVA");
        assert_eq!(doc, None);
    }
}
