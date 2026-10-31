//! O registro de diagnóstico: um JSONL por execução, feito para ser anexado a
//! um relato de erro. Por isso a redação é a regra, não um extra:
//!
//! - **nunca gravados**, nem no modo cru: senha, PIN, OTP e os dados do titular
//!   que o servidor ecoa (nome, CPF, RG, e-mail...). Nem o tamanho aparece;
//! - **impressão digital** (`<oculto len=N sha256=abcdef12>`): tokens e o
//!   `Authorization`, a menos que `REMOTEID_DIAG_CRU=1`, e sempre o serial do
//!   certificado e a assinatura devolvida. Dá para ver que é o mesmo token da
//!   linha de cima sem ver o token.
//!
//! Ficam em claro o emissor e as datas de validade: é com eles que se
//! diagnostica certificado vencido ou de outra AC. Uma falha ao gravar nunca
//! derruba a operação que o registro deveria explicar.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Map, Value, json};

use crate::cripto::sha256;

/// Desliga a máscara dos tokens, para investigar o protocolo na própria
/// máquina. Os segredos e os dados do titular continuam fora.
pub const ENV_CRU: &str = "REMOTEID_DIAG_CRU";

/// Quantos arquivos de execução ficam; os mais antigos são apagados.
const MANTER: usize = 20;

const SEGREDOS: &[&str] = &["senha", "password", "pin", "otp", "tokenotp"];

const DADOS_DO_TITULAR: &[&str] = &[
    "nome",
    "titular",
    "cpf",
    "rg",
    "email",
    "datanascimento",
    "orgaoexpedidor",
    "ufexpedidor",
    "tituloeleitor",
    "pispasep",
    "cei",
    "upn",
    "municipioeleitoral",
    "zonaeleitoral",
    "secaoeleitoral",
    "responsavelcnpj",
    "nomeempresarial",
];

const CREDENCIAIS: &[&str] = &[
    "token",
    "sessiontoken",
    "authorization",
    "autorizacao",
    "chaveprivada",
];

/// O serial aparece com três nomes no protocolo, e o `keyName` o contém. O
/// `base64` da carteira é o certificado inteiro, com o nome e o CPF do titular
/// dentro: em base64 eles só parecem ilegíveis.
const IDENTIFICADORES: &[&str] = &[
    "numeroserie",
    "numeroseriecertificado",
    "serialnumber",
    "keyname",
    "base64",
    "signaturebase64",
];

/// Aplica a redação a um valor, recursivamente, pelo nome de cada campo.
pub fn redigir(valor: &Value, cru: bool) -> Value {
    match valor {
        Value::Object(campos) => Value::Object(
            campos
                .iter()
                .map(|(k, v)| {
                    let nome = k.to_lowercase();
                    let em = |grupo: &[&str]| grupo.contains(&nome.as_str());
                    let redigido = if em(SEGREDOS) || em(DADOS_DO_TITULAR) {
                        json!(mascara(v))
                    } else if em(IDENTIFICADORES) || (!cru && em(CREDENCIAIS)) {
                        json!(impressao_digital(v))
                    } else {
                        redigir(v, cru)
                    };
                    (k.clone(), redigido)
                })
                .collect(),
        ),
        Value::Array(itens) => Value::Array(itens.iter().map(|v| redigir(v, cru)).collect()),
        outro => outro.clone(),
    }
}

fn mascara(valor: &Value) -> &'static str {
    match valor {
        Value::Null => "<ausente>",
        Value::String(s) if s.is_empty() => "<vazio>",
        _ => "<redigido>",
    }
}

fn impressao_digital(valor: &Value) -> String {
    let texto = match valor {
        Value::Null => return "<ausente>".into(),
        Value::String(s) => s.clone(),
        outro => outro.to_string(),
    };
    if texto.is_empty() {
        return "<vazio>".into();
    }
    let hash: String = sha256(texto.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("<oculto len={} sha256={hash}>", texto.len())
}

pub struct Diagnostico {
    arquivo: Option<Mutex<fs::File>>,
    caminho: Option<PathBuf>,
    cru: bool,
}

impl Diagnostico {
    /// Não grava nada: para quem não quer registro, como os testes.
    pub fn inerte() -> Diagnostico {
        Diagnostico {
            arquivo: None,
            caminho: None,
            cru: false,
        }
    }

    /// Abre o arquivo desta execução em `diretorio` e apaga os mais antigos
    /// que [`MANTER`].
    pub fn abrir(diretorio: &Path) -> Diagnostico {
        let cru = std::env::var(ENV_CRU).is_ok_and(|v| v == "1");
        let caminho = diretorio.join(format!("{}-{}.jsonl", agora(), std::process::id()));
        let arquivo = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(diretorio)
            .and_then(|()| {
                fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .open(&caminho)
            });
        match arquivo {
            Ok(arquivo) => {
                podar(diretorio);
                Diagnostico {
                    arquivo: Some(Mutex::new(arquivo)),
                    caminho: Some(caminho),
                    cru,
                }
            }
            Err(_) => Diagnostico::inerte(),
        }
    }

    pub fn caminho(&self) -> Option<&Path> {
        self.caminho.as_deref()
    }

    pub fn evento(&self, tipo: &str, campos: Value) {
        let Some(arquivo) = &self.arquivo else {
            return;
        };
        let mut linha = Map::new();
        linha.insert("t".into(), json!(agora()));
        linha.insert("evento".into(), json!(tipo));
        if let Value::Object(campos) = redigir(&campos, self.cru) {
            linha.extend(campos);
        }
        if let Ok(mut arquivo) = arquivo.lock() {
            let _ = writeln!(arquivo, "{}", Value::Object(linha));
        }
    }
}

fn podar(diretorio: &Path) {
    let Ok(entradas) = fs::read_dir(diretorio) else {
        return;
    };
    let mut arquivos: Vec<PathBuf> = entradas
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    // O nome começa com o epoch: a ordem do nome é a do tempo.
    arquivos.sort();
    let sobra = arquivos.len().saturating_sub(MANTER);
    for velho in &arquivos[..sobra] {
        let _ = fs::remove_file(velho);
    }
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segredos_nunca_aparecem_nem_no_modo_cru() {
        let corpo = json!({"desktopCode": "DC", "pin": "1234", "otp": "999999",
            "senha": "s3nh4", "nome": "Fulana", "Cpf": "12345678900"});
        let saida = redigir(&corpo, true).to_string();
        for segredo in ["1234", "999999", "s3nh4", "Fulana", "12345678900"] {
            assert!(!saida.contains(segredo), "{segredo} vazou: {saida}");
        }
        assert!(saida.contains("DC"), "o resto continua legível: {saida}");
    }

    #[test]
    fn token_vira_impressao_digital_comparavel() {
        let a = redigir(&json!({"token": "sessaoAssinatura;327989"}), false);
        let b = redigir(&json!({"token": "sessaoAssinatura;327989"}), false);
        let c = redigir(&json!({"token": "outro"}), false);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.to_string().contains("327989"));
        // No modo cru o token aparece; o serial, nunca.
        let cru = redigir(&json!({"token": "t1", "serialNumber": "SN9"}), true).to_string();
        assert!(cru.contains("t1") && !cru.contains("SN9"), "{cru}");
    }

    #[test]
    fn redige_dentro_de_listas_e_objetos() {
        let corpo = json!({"idArray": [{"signatureBase64": "QUJD", "id": "0"}],
            "certificate": {"titular": "Fulana", "emissor": "AC X"}});
        let saida = redigir(&corpo, false).to_string();
        assert!(
            !saida.contains("QUJD") && !saida.contains("Fulana"),
            "{saida}"
        );
        assert!(saida.contains("AC X"), "o emissor fica em claro: {saida}");
    }
}
