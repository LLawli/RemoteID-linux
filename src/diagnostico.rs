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
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use crate::cripto::sha256;

/// Desliga a máscara dos tokens, para investigar o protocolo na própria
/// máquina. Os segredos e os dados do titular continuam fora.
pub const ENV_CRU: &str = "REMOTEID_DIAG_CRU";

/// Por quanto tempo um registro fica: o bastante para a pessoa notar o erro,
/// relatar e rodar `remoteid diagnostico`.
const IDADE_MAXIMA: u64 = 30 * 24 * 60 * 60;

/// O teto da pasta inteira; acima dele, os mais antigos saem primeiro.
const TETO_TOTAL: u64 = 64 * 1024 * 1024;

/// O teto de um arquivo, contra um processo que fica dias aberto, como o
/// navegador que carrega o módulo.
const TETO_ARQUIVO: u64 = 8 * 1024 * 1024;

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

/// O registro desta execução. Clonar é barato e as cópias escrevem no mesmo
/// arquivo: o módulo PKCS#11 e o motor que ele abre dividem um só.
#[derive(Clone, Default)]
pub struct Diagnostico(Option<Arc<Interno>>);

struct Interno {
    diretorio: PathBuf,
    caminho: PathBuf,
    processo: String,
    cru: bool,
    arquivo: Mutex<Arquivo>,
}

/// O arquivo só nasce na primeira linha: quem abre o registro e não tem nada
/// a dizer, como a janela que só mostrou a carteira, não deixa arquivo.
enum Arquivo {
    Fechado,
    Aberto {
        arquivo: fs::File,
        gravados: u64,
    },
    /// Não abriu, ou passou do teto: o resto da execução fica sem registro.
    Encerrado,
}

impl Diagnostico {
    /// Não grava nada: para quem não quer registro, como os testes.
    pub fn inerte() -> Diagnostico {
        Diagnostico(None)
    }

    /// O registro desta execução em `diretorio`. `processo` diz quem grava (a
    /// janela, o módulo, um comando do terminal) e vai no evento de início.
    pub fn abrir(diretorio: &Path, processo: &str) -> Diagnostico {
        let cru = std::env::var(ENV_CRU).is_ok_and(|v| v == "1");
        // Dentro do Flatpak cada comando é o PID 2 do próprio sandbox: os
        // nanossegundos separam dois que começam no mesmo segundo.
        let instante = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let nome = format!(
            "{}-{:09}-{}.jsonl",
            instante.as_secs(),
            instante.subsec_nanos(),
            std::process::id()
        );
        let caminho = diretorio.join(nome);
        Diagnostico(Some(Arc::new(Interno {
            diretorio: diretorio.to_path_buf(),
            caminho,
            processo: processo.to_string(),
            cru,
            arquivo: Mutex::new(Arquivo::Fechado),
        })))
    }

    /// Onde a execução grava, exista o arquivo ou não.
    pub fn caminho(&self) -> Option<&Path> {
        self.0.as_ref().map(|i| i.caminho.as_path())
    }

    pub fn evento(&self, tipo: &str, campos: Value) {
        self.evento_em(agora(), tipo, campos);
    }

    /// Um evento que aconteceu em `t` e só agora é gravado.
    pub fn evento_em(&self, t: u64, tipo: &str, campos: Value) {
        let Some(interno) = &self.0 else {
            return;
        };
        let mut linha = Map::new();
        linha.insert("t".into(), json!(t));
        linha.insert("evento".into(), json!(tipo));
        if let Value::Object(campos) = redigir(&campos, interno.cru) {
            linha.extend(campos);
        }
        let mut arquivo = interno.arquivo.lock().unwrap_or_else(|e| e.into_inner());
        if let Arquivo::Fechado = *arquivo {
            *arquivo = interno.criar();
        }
        let Arquivo::Aberto {
            arquivo: f,
            gravados,
        } = &mut *arquivo
        else {
            return;
        };
        let mut texto = Value::Object(linha).to_string();
        texto.push('\n');
        if *gravados + texto.len() as u64 > TETO_ARQUIVO {
            let aviso = json!({"t": agora(), "evento": "truncado", "teto": TETO_ARQUIVO});
            let _ = writeln!(f, "{aviso}");
            *arquivo = Arquivo::Encerrado;
            return;
        }
        if f.write_all(texto.as_bytes()).is_ok() {
            *gravados += texto.len() as u64;
        }
    }
}

impl Interno {
    /// Cria o arquivo com o evento de início, e poda os antigos.
    fn criar(&self) -> Arquivo {
        let criado = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.diretorio)
            .and_then(|()| {
                fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .open(&self.caminho)
            });
        let Ok(mut arquivo) = criado else {
            return Arquivo::Encerrado;
        };
        podar(&self.diretorio, &self.caminho, agora());
        let mut inicio = json!({"t": agora(), "evento": "inicio", "processo": self.processo});
        if let (Value::Object(linha), Value::Object(ambiente)) = (&mut inicio, ambiente()) {
            linha.extend(ambiente);
        }
        let texto = format!("{inicio}\n");
        let gravados = match arquivo.write_all(texto.as_bytes()) {
            Ok(()) => texto.len() as u64,
            Err(_) => 0,
        };
        Arquivo::Aberto { arquivo, gravados }
    }
}

/// Onde e com o quê esta execução roda. Nada aqui identifica a pessoa: nem
/// usuário, nem máquina, nem caminho da pasta pessoal.
pub fn ambiente() -> Value {
    let flatpak = fs::read_to_string("/.flatpak-info").unwrap_or_default();
    let chave = |secao: &str, nome: &str| -> Option<String> {
        let mut dentro = false;
        for linha in flatpak.lines() {
            if let Some(s) = linha.strip_prefix('[') {
                dentro = s.trim_end_matches(']') == secao;
            } else if dentro
                && let Some((k, v)) = linha.split_once('=')
                && k.trim() == nome
            {
                return Some(v.trim().to_string());
            }
        }
        None
    };
    // Dentro do Flatpak, o /etc é o do runtime; o do sistema fica em
    // /run/host.
    let sistema = ["/run/host/os-release", "/etc/os-release"]
        .iter()
        .find_map(|c| fs::read_to_string(c).ok())
        .and_then(|texto| {
            texto.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        });
    let ler = |c: &str| fs::read_to_string(c).ok().map(|s| s.trim().to_string());
    let var = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
    json!({
        "versao": env!("CARGO_PKG_VERSION"),
        "aplicativo": crate::id_do_aplicativo(),
        "hospedeiro": var("FLATPAK_ID"),
        "runtime": chave("Application", "runtime"),
        "flatpak": chave("Instance", "flatpak-version"),
        "extensoes": chave("Instance", "app-extensions"),
        "sistema": sistema,
        "kernel": ler("/proc/sys/kernel/osrelease"),
        "comando": ler("/proc/self/comm"),
        "pid": std::process::id(),
        "sessao": var("XDG_SESSION_TYPE"),
        "desktop": var("XDG_CURRENT_DESKTOP"),
        "servidor_falso": var(crate::caminhos::ENV_SERVIDOR).is_some(),
    })
}

/// Apaga o que passou de [`IDADE_MAXIMA`] e, do mais velho para o mais novo,
/// o que passa de [`TETO_TOTAL`] somado. `atual` fica sempre.
fn podar(diretorio: &Path, atual: &Path, agora: u64) {
    let Ok(entradas) = fs::read_dir(diretorio) else {
        return;
    };
    let mut arquivos: Vec<(u64, u64, PathBuf)> = entradas
        .flatten()
        .filter(|e| e.path() != atual)
        .filter_map(|e| {
            let metadados = e.metadata().ok().filter(|m| m.is_file())?;
            let modificado = metadados
                .modified()
                .ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some((modificado, metadados.len(), e.path()))
        })
        .collect();
    arquivos.sort();
    let mut total: u64 = arquivos.iter().map(|(_, tamanho, _)| tamanho).sum();
    for (modificado, tamanho, caminho) in &arquivos {
        let velho = agora.saturating_sub(*modificado) > IDADE_MAXIMA;
        if (velho || total > TETO_TOTAL) && fs::remove_file(caminho).is_ok() {
            total -= tamanho;
        }
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

    fn diretorio(nome: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remoteid-diag-{}-{nome}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn criar(caminho: &Path, tamanho: usize, idade: u64) {
        let arquivo = fs::File::create(caminho).unwrap();
        arquivo.set_len(tamanho as u64).unwrap();
        let quando = std::time::SystemTime::now() - std::time::Duration::from_secs(idade);
        arquivo.set_modified(quando).unwrap();
    }

    #[test]
    fn dois_registros_do_mesmo_processo_nao_dividem_arquivo() {
        let dir = diretorio("nomes");
        let a = Diagnostico::abrir(&dir, "teste");
        let b = Diagnostico::abrir(&dir, "teste");
        assert_ne!(a.caminho(), b.caminho());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sem_evento_nao_ha_arquivo_e_o_primeiro_e_o_inicio() {
        let dir = diretorio("preguicoso");
        let d = Diagnostico::abrir(&dir, "teste");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        d.clone().evento("rede", json!({"erro": "x"}));
        let texto = fs::read_to_string(d.caminho().unwrap()).unwrap();
        let linhas: Vec<Value> = texto
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(linhas.len(), 2, "{texto}");
        assert_eq!(linhas[0]["evento"], "inicio");
        assert_eq!(linhas[0]["processo"], "teste");
        assert_eq!(linhas[0]["versao"], env!("CARGO_PKG_VERSION"));
        assert_eq!(linhas[1]["evento"], "rede");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn poda_por_idade_e_pelo_teto_do_mais_velho_para_o_mais_novo() {
        let dir = diretorio("poda");
        let dia = 24 * 60 * 60;
        let mega = 1024 * 1024;
        criar(&dir.join("vencido.jsonl"), 10, IDADE_MAXIMA + dia);
        criar(&dir.join("velho.jsonl"), 40 * mega, 3 * dia);
        criar(&dir.join("medio.jsonl"), 30 * mega, 2 * dia);
        criar(&dir.join("novo.jsonl"), 30 * mega, dia);
        criar(&dir.join("harness-1.txt"), 10, dia / 2);
        let atual = dir.join("atual.jsonl");
        criar(&atual, 10, IDADE_MAXIMA + dia);
        podar(&dir, &atual, agora());
        let mut ficaram: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        ficaram.sort();
        // 100 MiB passam do teto de 64: sai o mais velho, e os 60 restantes
        // cabem.
        assert_eq!(
            ficaram,
            ["atual.jsonl", "harness-1.txt", "medio.jsonl", "novo.jsonl"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn um_arquivo_para_de_crescer_no_teto() {
        let dir = diretorio("teto");
        let d = Diagnostico::abrir(&dir, "teste");
        let grande = "x".repeat(1024 * 1024);
        for _ in 0..TETO_ARQUIVO / (1024 * 1024) + 2 {
            d.evento("grande", json!({ "dado": grande }));
        }
        let tamanho = fs::metadata(d.caminho().unwrap()).unwrap().len();
        assert!(tamanho <= TETO_ARQUIVO + 1024, "{tamanho}");
        let texto = fs::read_to_string(d.caminho().unwrap()).unwrap();
        assert!(texto.lines().last().unwrap().contains("truncado"));
        let _ = fs::remove_dir_all(&dir);
    }
}
