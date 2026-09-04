//! Modelos planos que as telas consomem. Sem serde, sem protocolo: o binário
//! traduz o `SucessoResposta::Status` do daemon para cá, e o modo `--preview`
//! preenche com os `mock_*` abaixo. Assim a lib de telas fica independente do
//! transporte e testável só com dados de brincadeira.

/// Um certificado, já resumido para exibição (o DER cru não entra na UI).
#[derive(Debug, Clone)]
pub struct Certificado {
    /// Nome do titular (o que aparece em "Assinar como ...").
    pub titular: String,
    /// Emissor (AC), legível.
    pub emissor: String,
    /// Número de série, em hexa ou decimal como veio.
    pub serial: String,
    /// `keyName` do protocolo (`<serial>;<issuer DN>`), a chave técnica.
    pub key_name: String,
}

/// Uma sessão em cache (o `sessionToken` por certificado), resumida.
#[derive(Debug, Clone)]
pub struct Sessao {
    pub cert_key: String,
    /// Epoch de emissão do token, se foi possível parsear.
    pub emitido_em: Option<u64>,
    /// Quando o daemon usou/validou a sessão pela última vez (epoch).
    pub visto_em: u64,
}

/// O estado que o painel principal mostra. Espelha o
/// `SucessoResposta::Status` do protocolo, mas sem depender dele.
#[derive(Debug, Clone)]
pub struct EstadoApp {
    /// `true` quando login+registro+carteira já rodaram (há certificado).
    pub preparado: bool,
    pub titular: Option<String>,
    pub codigo_desktop: Option<String>,
    pub certificados: Vec<Certificado>,
    /// `key_name` do certificado padrão escolhido, quando a carteira tem mais de
    /// um e o usuário escolheu. `None` = ainda não escolheu (a janela pede) ou
    /// só há um certificado.
    pub certificado_ativo: Option<String>,
    pub sessoes: Vec<Sessao>,
}

/// As configurações editáveis na aba de configurações (decisão em
/// [[remoteid-app-gtk-decisoes-tomadas]]). A persistência real
/// (`~/.config/remoteid/config.toml`) é da janela; a lib só desenha.
#[derive(Debug, Clone)]
pub struct ConfigApp {
    /// Duração do cache do PIN em minutos (0 = desligado, faixa 0–60).
    pub cache_pin_min: u32,
    /// TTL hipotético do `sessionToken` em minutos (pré-filtro do cache).
    pub ttl_sessao_min: u32,
    /// `nomeAplicacaoDesktop` enviado ao RemoteID.
    pub nome_aplicacao: String,
    /// Caminho do diretório de log de diagnóstico (só leitura na UI).
    pub caminho_log: String,
}

impl EstadoApp {
    /// Preview: instalação pronta, um certificado, uma sessão em cache.
    pub fn mock_preparado() -> EstadoApp {
        EstadoApp {
            preparado: true,
            titular: Some("MARIA SILVA:12345678900".into()),
            codigo_desktop: Some("8f3a1c2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b".into()),
            certificados: vec![Certificado {
                titular: "MARIA SILVA:12345678900".into(),
                emissor: "AC OAB G3".into(),
                serial: "3A:1F:9C:22:04:8B".into(),
                key_name: "3A1F9C22048B;CN=AC OAB G3,O=ICP-Brasil,C=BR".into(),
            }],
            certificado_ativo: None,
            sessoes: vec![Sessao {
                cert_key: "3A1F9C22048B;AC OAB G3".into(),
                emitido_em: Some(1_756_900_000),
                visto_em: 1_756_900_600,
            }],
        }
    }

    /// Preview: recém-instalado, sem preparar (empurra pro wizard de login).
    pub fn mock_nao_preparado() -> EstadoApp {
        EstadoApp {
            preparado: false,
            titular: None,
            codigo_desktop: None,
            certificados: vec![],
            certificado_ativo: None,
            sessoes: vec![],
        }
    }

    /// Preview: dois certificados na carteira, para exercitar a tela de
    /// seleção de token.
    pub fn mock_multi_token() -> EstadoApp {
        EstadoApp {
            preparado: true,
            titular: Some("MARIA SILVA:12345678900".into()),
            codigo_desktop: Some("8f3a1c2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b".into()),
            certificados: vec![
                Certificado {
                    titular: "MARIA SILVA:12345678900".into(),
                    emissor: "AC OAB G3".into(),
                    serial: "3A:1F:9C:22:04:8B".into(),
                    key_name: "3A1F9C22048B;CN=AC OAB G3".into(),
                },
                Certificado {
                    titular: "MARIA SILVA:12345678900".into(),
                    emissor: "AC Certisign RFB G5".into(),
                    serial: "7C:88:1E:0A:D3:44".into(),
                    key_name: "7C881E0AD344;CN=AC Certisign RFB G5".into(),
                },
            ],
            certificado_ativo: None,
            sessoes: vec![],
        }
    }
}

impl ConfigApp {
    /// Preview: os padrões da decisão (cache 5 min, TTL 15 min, nome fixo).
    pub fn mock() -> ConfigApp {
        ConfigApp {
            cache_pin_min: 5,
            ttl_sessao_min: 15,
            nome_aplicacao: "RemoteID-linux".into(),
            caminho_log: "~/.local/state/remoteid/diag".into(),
        }
    }
}
