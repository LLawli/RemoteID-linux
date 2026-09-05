//! Protocolo JSON do socket do daemon RemoteID-linux.
//!
//! Crate-folha compartilhado: o **daemon** (`remoteid-daemon`) desserializa
//! [`Requisicao`] e serializa [`Resposta`]; os **clientes** (a janela GTK e o
//! futuro braço de produção do `C_Sign` no módulo PKCS#11) fazem o inverso.
//! Por isso [`Requisicao`] deriva `Serialize` **e** `Deserialize`, e este
//! crate não puxa GTK nem os crates de domínio: o `cdylib` do PKCS#11 não pode
//! linkar GTK.
//!
//! Framing: uma mensagem JSON por linha, terminada em `\n`. Escolhido em vez de
//! comprimento-prefixado por duas razões: o cliente principal (o módulo
//! PKCS#11) vai escrever uma mensagem e ler UMA resposta por chamada do
//! `C_Sign` — sem streaming — e `BufReader::read_line` no daemon casa
//! perfeitamente com isso; e "uma linha por mensagem" torna o tráfego
//! auditável com `socat` sem código extra.
//!
//! Discriminador: campo `op` (string). Um socket só, dois grupos de verbos
//! (o do módulo — [`Requisicao::Sign`] — e os administrativos, que a janela
//! GTK chama). Ver [[remoteid-app-gtk-forma-de-operacao]] para a decisão.

use serde::{Deserialize, Serialize};

/// Requisição do cliente. `#[serde(tag = "op")]` faz o campo `op` ser o
/// discriminador da enum: cada variante tem o próprio conjunto de campos, e o
/// serde recusa em compile-time uma mensagem que misture campos de variantes.
///
/// Deriva `Serialize` (o cliente monta) e `Deserialize` (o daemon lê).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Requisicao {
    /// Assinar um bloco. Verbo do módulo PKCS#11.
    ///
    /// `algoritmo` espelha, verbatim, o campo `algorithm` do
    /// `requestHashSessionSignature`: `"SHA256"` (o padrão, quando ausente)
    /// diz que `digest_b64` é o hash de 32 bytes e o HSM embrulha em
    /// DigestInfo; `""` (vazio) é o modo CRU, em que `digest_b64` é o bloco
    /// pronto (o DigestInfo que o `CKM_RSA_PKCS` recebe, de até 245 bytes) e
    /// o HSM só aplica o padding. É o que permite `MD5withRSA` no PJeOffice.
    /// Este crate não interpreta o valor: os literais e a regra de tamanho
    /// moram no domínio do protocolo do servidor (`Algoritmo`), e o daemon
    /// converte na borda. Opcional para um módulo antigo continuar falando
    /// com um daemon novo durante uma atualização.
    ///
    /// `hospedeiro` é o nome do processo que pediu (para diagnóstico e para
    /// registrar no diag qual app disparou o `C_Sign`). Opcional: se
    /// omitido, o daemon lê `SO_PEERCRED` do socket e resolve pelo
    /// `/proc/<pid>/comm` do cliente.
    Sign {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        algoritmo: Option<String>,
        /// O que assinar, em base64 padrão: o SHA-256 (32 bytes → 44 chars)
        /// ou, no modo cru, o bloco pronto. O nome ficou por compatibilidade
        /// com o módulo de antes do modo cru.
        digest_b64: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hospedeiro: Option<String>,
    },
    /// Estado da instalação, para o painel da janela GTK.
    Status,
    /// Reset LEVE: invalida o `sessionToken` cached do certificado ativo.
    /// A próxima assinatura vai pedir PIN+OTP.
    ReautorizarProxima,
    /// Reset PESADO: apaga o `state.json` e a chave da instalação. Vai
    /// exigir novo login+registro+carteira. Confirmação é responsabilidade
    /// do chamador (a janela GTK mostra o diálogo vermelho).
    Reinstalar,
    /// Escolhe o certificado padrão (quando a carteira tem mais de um). O
    /// `key_name` é o do [`CertificadoResumo`]. Persiste como preferência local;
    /// a próxima assinatura passa a usar esse certificado. Responde `Ack`.
    EscolherCertificado { key_name: String },
    /// Encerra o daemon. Útil pra testes; a janela também usa quando o
    /// usuário pede "sair completamente".
    Encerrar,
}

/// Resposta do daemon. Sempre carrega `ok`, e ou `erro`/`codigo` (falha) ou os
/// campos específicos da operação (sucesso).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Resposta {
    Sucesso(SucessoResposta),
    Falha {
        ok: bool, // sempre false, existe para o cliente discriminar
        erro: String,
        codigo: CodigoErro,
    },
}

impl Resposta {
    pub fn falha(codigo: CodigoErro, erro: impl Into<String>) -> Resposta {
        Resposta::Falha {
            ok: false,
            erro: erro.into(),
            codigo,
        }
    }
}

/// Corpo dos casos de sucesso. Um por variante de [`Requisicao`], mais o
/// `ack` genérico para as operações sem retorno.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SucessoResposta {
    Sign {
        ok: bool, // sempre true
        /// A assinatura RSA CRUA (256 bytes para RSA-2048), em base64.
        /// Não é PKCS#7: quem quiser CAdES monta em volta.
        assinatura_b64: String,
        /// `true` se a assinatura saiu do cache (não pediu PIN+OTP).
        /// O módulo repassa para o diag do daemon já sabe, mas ajuda a
        /// janela a mostrar "última assinatura: sem PIN".
        cache_hit: bool,
    },
    Status {
        ok: bool,
        preparado: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        codigo_desktop: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        titular: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        certificados: Vec<CertificadoResumo>,
        /// `key_name` do certificado padrão escolhido, quando há mais de um e o
        /// usuário escolheu. A UI marca esse na tela de seleção.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        certificado_ativo: Option<String>,
        /// Cache de sessões por certificado.
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        sessoes: Vec<SessaoResumo>,
    },
    Ack {
        ok: bool, // sempre true
    },
}

/// Um item leve de certificado para a UI (sem base64 do DER, que é grande).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificadoResumo {
    pub key_name: String,
    pub serial_number: String,
    pub issue: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ous: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validade: Option<String>,
}

/// O que a UI mostra na linha "sessão em cache" do painel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessaoResumo {
    pub cert_key: String,
    /// Epoch do token, se parseável. Sem ele, `None` — a UI mostra "sem
    /// data de emissão declarada".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitido_em: Option<u64>,
    pub visto_em: u64,
}

/// Códigos estáveis para o cliente ramificar. Strings, não inteiros, porque
/// aparecem no diag e no log da janela e legibilidade paga o custo do byte.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodigoErro {
    /// A mensagem não passou no parser. O cliente mandou um JSON malformado
    /// ou uma variante desconhecida.
    RequisicaoInvalida,
    /// Antes de assinar é preciso `login` + `registrar` + `carteira`. A
    /// janela GTK vai empurrar pro wizard nesse caso.
    NaoPreparado,
    /// Nenhum certificado disponível, `algoritmo` desconhecido, ou o
    /// `digest_b64` não tem o tamanho que o algoritmo exige.
    EntradaInvalida,
    /// Pedimos PIN+OTP e o usuário cancelou o diálogo.
    Cancelado,
    /// Servidor RemoteID recusou. `erro` traz a mensagem, com hint quando
    /// existir.
    ErroServidor,
    /// Rede indisponível ou timeout.
    ErroRede,
    /// Bug ou situação inesperada. Sempre acompanhado do arquivo do diag.
    ErroInterno,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sign_com_hospedeiro() {
        let r: Requisicao =
            serde_json::from_str(r#"{"op":"sign","digest_b64":"AAA=","hospedeiro":"papers"}"#)
                .unwrap();
        match r {
            Requisicao::Sign {
                algoritmo,
                digest_b64,
                hospedeiro,
            } => {
                assert_eq!(digest_b64, "AAA=");
                assert_eq!(hospedeiro.as_deref(), Some("papers"));
                assert!(algoritmo.is_none(), "sem o campo, o daemon usa o padrão");
            }
            _ => panic!("parseou variante errada"),
        }
    }

    #[test]
    fn parse_sign_sem_hospedeiro_e_opcional() {
        let r: Requisicao = serde_json::from_str(r#"{"op":"sign","digest_b64":"AAA="}"#).unwrap();
        match r {
            Requisicao::Sign { hospedeiro, .. } => assert!(hospedeiro.is_none()),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_sign_com_algoritmo_vazio_preserva_a_string_vazia() {
        // O modo cru é a string VAZIA, e ela não pode virar `None` no caminho:
        // `None` é "o padrão" (SHA256), o oposto do que o módulo pediu.
        let r: Requisicao =
            serde_json::from_str(r#"{"op":"sign","algoritmo":"","digest_b64":"AAA="}"#).unwrap();
        match r {
            Requisicao::Sign { algoritmo, .. } => assert_eq!(algoritmo.as_deref(), Some("")),
            _ => panic!(),
        }
    }

    #[test]
    fn sign_faz_ida_e_volta_pela_serializacao() {
        // O cliente serializa, o daemon desserializa: o round-trip tem que
        // fechar, senão a janela e o daemon falam línguas diferentes.
        let original = Requisicao::Sign {
            algoritmo: Some("".into()),
            digest_b64: "AAA=".into(),
            hospedeiro: Some("papers".into()),
        };
        let linha = serde_json::to_string(&original).unwrap();
        assert!(linha.contains(r#""op":"sign"#));
        assert!(linha.contains(r#""algoritmo":"""#));
        let volta: Requisicao = serde_json::from_str(&linha).unwrap();
        match volta {
            Requisicao::Sign {
                algoritmo,
                digest_b64,
                hospedeiro,
            } => {
                assert_eq!(algoritmo.as_deref(), Some(""));
                assert_eq!(digest_b64, "AAA=");
                assert_eq!(hospedeiro.as_deref(), Some("papers"));
            }
            _ => panic!(),
        }

        // Sem algoritmo, o campo nem aparece: é a mensagem do módulo antigo.
        let antigo = Requisicao::Sign {
            algoritmo: None,
            digest_b64: "AAA=".into(),
            hospedeiro: None,
        };
        assert_eq!(
            serde_json::to_string(&antigo).unwrap(),
            r#"{"op":"sign","digest_b64":"AAA="}"#
        );
    }

    #[test]
    fn status_serializa_com_op_status() {
        let linha = serde_json::to_string(&Requisicao::Status).unwrap();
        assert_eq!(linha, r#"{"op":"status"}"#);
    }

    #[test]
    fn parse_status_sem_campos() {
        let r: Requisicao = serde_json::from_str(r#"{"op":"status"}"#).unwrap();
        assert!(matches!(r, Requisicao::Status));
    }

    #[test]
    fn op_desconhecido_falha_o_parse_em_vez_de_ignorar() {
        // Sem isto, uma requisição malformada viraria uma variante default
        // silenciosa e o daemon executaria a operação errada.
        let r: Result<Requisicao, _> = serde_json::from_str(r#"{"op":"drop_tables"}"#);
        assert!(r.is_err());
    }

    #[test]
    fn resposta_falha_serializa_com_ok_false() {
        let r = Resposta::falha(CodigoErro::Cancelado, "usuário fechou o diálogo");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""ok":false"#));
        assert!(s.contains(r#""codigo":"CANCELADO"#));
    }

    #[test]
    fn resposta_sign_traz_cache_hit() {
        let r = Resposta::Sucesso(SucessoResposta::Sign {
            ok: true,
            assinatura_b64: "AAA=".into(),
            cache_hit: true,
        });
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""cache_hit":true"#));
        assert!(s.contains(r#""op":"sign"#));
    }
}
