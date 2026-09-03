//! Log de diagnóstico detalhado, em arquivo, fora do caminho do usuário.
//!
//! O motor grava um JSONL por execução em
//! `$XDG_STATE_HOME/remoteid-linux/diag/` (por padrão
//! `~/.local/state/remoteid-linux/diag/`). Nada disso vai para o terminal: a
//! saída do CLI continua enxuta, e o arquivo existe para ser ANEXADO a um
//! relatório de bug depois, quando o app GTK tiver esse botão.
//!
//! # Por que JSONL e um arquivo por execução
//!
//! Uma linha por evento, cada uma um objeto JSON completo: dá para `tail`,
//! `grep` e `jq` sem parser próprio, e um arquivo truncado no meio (crash,
//! disco cheio) continua legível até a última linha inteira. Um arquivo por
//! execução torna "me manda o log daquela vez que falhou" uma operação de
//! copiar UM arquivo, sem recortar intervalo de tempo de um log rolante.
//!
//! # Redação
//!
//! O log é feito para ser ENVIADO a terceiros, então a redação é o padrão e
//! não um extra:
//!
//! - **Sempre mascarados, sem exceção:** `senha`, `pin`, `otp` e variantes.
//!   Nunca são necessários para diagnosticar protocolo, e o PIN do certificado
//!   é permanente (vazá-lo é pior que vazar um OTP, que expira em ~30s).
//! - **Mascarados por padrão:** tokens e o header `Authorization`. Em vez de
//!   sumirem, viram uma impressão digital `<oculto len=N sha256=abcdef12>`, que
//!   permite responder "é o mesmo token da linha de cima?" e "o Bearer mudou
//!   entre as tentativas?" sem revelar o valor.
//! - `REMOTEID_DIAG_RAW=1` desliga só a máscara dos tokens, para investigação
//!   de protocolo na própria máquina. Os segredos do primeiro item continuam
//!   mascarados mesmo assim.
//!
//! A canônica assinada NUNCA é gravada crua: no `tokensessao` ela contém o PIN
//! e o OTP concatenados. Gravamos o SHA-256 dela e o comprimento, que é o que
//! responde "o cliente e o servidor calcularam a mesma canônica?".

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::crypto::sha256;
use crate::error::Result;

/// Quantos arquivos de execução manter antes de apagar os mais antigos.
const MANTER_EXECUCOES: usize = 20;

/// Campos cujo valor nunca é gravado, nem com `REMOTEID_DIAG_RAW`.
const SEGREDOS: &[&str] = &["senha", "password", "passwd", "pwd", "pin", "otp"];

/// Campos gravados como impressão digital, a menos que `REMOTEID_DIAG_RAW=1`.
const CREDENCIAIS: &[&str] = &["token", "sessiontoken", "authorization", "chaveprivada"];

pub struct Diag {
    arquivo: Option<Mutex<fs::File>>,
    caminho: Option<PathBuf>,
    /// `REMOTEID_DIAG_RAW=1`: não mascara tokens (segredos seguem mascarados).
    cru: bool,
}

impl Diag {
    /// Abre um arquivo novo para esta execução dentro de `dir`.
    ///
    /// Falhar aqui não pode derrubar o comando do usuário: se o diretório não
    /// puder ser criado, devolvemos um log inerte e a execução segue.
    pub fn abrir(dir: &Path) -> Diag {
        match Self::tentar_abrir(dir) {
            Ok(d) => d,
            Err(_) => Diag::inerte(),
        }
    }

    /// Um log que descarta tudo. Para testes e para o caso de disco indisponível.
    pub fn inerte() -> Diag {
        Diag { arquivo: None, caminho: None, cru: false }
    }

    fn tentar_abrir(dir: &Path) -> Result<Diag> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // O diretório guarda material sensível redigido, mas ainda assim
            // identificável (certificado, CPF): não é de leitura pública.
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let agora = epoch_segundos();
        let nome = format!("run-{agora}-{}.jsonl", std::process::id());
        let caminho = dir.join(nome);

        let mut opts = fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let arquivo = opts.open(&caminho)?;

        let diag = Diag {
            arquivo: Some(Mutex::new(arquivo)),
            caminho: Some(caminho),
            cru: std::env::var("REMOTEID_DIAG_RAW").as_deref() == Ok("1"),
        };
        podar(dir, MANTER_EXECUCOES);
        Ok(diag)
    }

    /// Caminho do arquivo desta execução, para o CLI dizer onde ele está.
    pub fn caminho(&self) -> Option<&Path> {
        self.caminho.as_deref()
    }

    /// Grava um evento. Erros de escrita são engolidos de propósito: um log de
    /// diagnóstico que derruba a operação que ele deveria diagnosticar é pior
    /// que log nenhum.
    pub fn evento(&self, tipo: &str, campos: Value) {
        let Some(arq) = &self.arquivo else { return };
        let t = epoch_segundos();
        let mut obj = Map::new();
        obj.insert("t".into(), json!(t));
        obj.insert("ts".into(), json!(iso8601(t)));
        obj.insert("evento".into(), json!(tipo));
        if let Value::Object(m) = self.redigir(&campos) {
            for (k, v) in m {
                obj.insert(k, v);
            }
        }
        let linha = match serde_json::to_string(&Value::Object(obj)) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(mut f) = arq.lock() {
            let _ = writeln!(f, "{linha}");
            let _ = f.flush();
        }
    }

    /// Aplica a política de redação a um valor arbitrário, recursivamente.
    pub fn redigir(&self, valor: &Value) -> Value {
        match valor {
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, v) in m {
                    let chave = k.to_lowercase();
                    if SEGREDOS.iter().any(|s| chave == *s) {
                        out.insert(k.clone(), json!(mascara_segredo(v)));
                    } else if !self.cru && CREDENCIAIS.iter().any(|s| chave == *s) {
                        out.insert(k.clone(), json!(impressao_digital(v)));
                    } else {
                        out.insert(k.clone(), self.redigir(v));
                    }
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(|v| self.redigir(v)).collect()),
            outro => outro.clone(),
        }
    }

    /// Registra a canônica de forma segura: só o hash e o tamanho.
    ///
    /// A canônica do `tokensessao` é a concatenação dos valores, o que inclui o
    /// PIN e o OTP em texto claro. O que se precisa saber num diagnóstico é se
    /// cliente e servidor calcularam a MESMA canônica, e para isso o hash basta.
    pub fn canonica(&self, rotulo: &str, canonical: &str, bearer: &str) {
        self.evento(
            "assinatura",
            json!({
                "rotulo": rotulo,
                "canonica_sha256": hex(&sha256(canonical.as_bytes())),
                "canonica_bytes": canonical.len(),
                "bearer_sha256": hex(&sha256(bearer.as_bytes())),
                "bearer_bytes": bearer.len(),
            }),
        );
    }
}

/// Segredo: nem o tamanho é informado (o tamanho de um PIN já é dica).
fn mascara_segredo(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() => "<vazio>".into(),
        Value::Null => "<ausente>".into(),
        _ => "<redigido>".into(),
    }
}

/// Credencial: tamanho e hash, o suficiente para comparar duas ocorrências.
fn impressao_digital(v: &Value) -> String {
    let texto = match v {
        Value::String(s) => s.clone(),
        Value::Null => return "<ausente>".into(),
        outro => outro.to_string(),
    };
    if texto.is_empty() {
        return "<vazio>".into();
    }
    let h = hex(&sha256(texto.as_bytes()));
    format!("<oculto len={} sha256={}>", texto.len(), &h[..8])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn epoch_segundos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Apaga os arquivos de execução mais antigos, mantendo os `manter` últimos.
fn podar(dir: &Path, manter: usize) {
    let Ok(entradas) = fs::read_dir(dir) else { return };
    let mut arquivos: Vec<PathBuf> = entradas
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("run-") && n.ends_with(".jsonl"))
        })
        .collect();
    if arquivos.len() <= manter {
        return;
    }
    // O nome começa com o epoch, então a ordem lexicográfica é a cronológica
    // para todos os timestamps do mesmo número de dígitos.
    arquivos.sort();
    let sobra = arquivos.len() - manter;
    for velho in arquivos.iter().take(sobra) {
        let _ = fs::remove_file(velho);
    }
}

/// Data ISO-8601 em UTC a partir do epoch, sem depender de crate de tempo.
///
/// Algoritmo `civil_from_days` de Howard Hinnant: desloca a origem para
/// 1º de março para que o dia bissexto caia no fim do ano deslocado, o que
/// elimina o caso especial de fevereiro.
pub fn iso8601(epoch: u64) -> String {
    let dias = (epoch / 86_400) as i64;
    let resto = epoch % 86_400;
    let (h, mi, s) = (resto / 3600, (resto % 3600) / 60, resto % 60);

    let z = dias + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formata_datas_conhecidas() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        // O `momento` mandado na carteira da run 210447 de 02/09/2026.
        assert_eq!(iso8601(1_788_393_921), "2026-09-03T00:05:21Z");
        // Um 29 de fevereiro, que é onde a aritmética de data costuma quebrar.
        assert_eq!(iso8601(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn pin_e_otp_nunca_aparecem_nem_no_modo_cru() {
        let mut d = Diag::inerte();
        d.cru = true;
        let corpo = serde_json::json!({
            "desktopCode": "DC", "pin": "1234", "otp": "999999", "push": false
        });
        let saida = d.redigir(&corpo).to_string();
        assert!(!saida.contains("1234"), "o PIN vazou: {saida}");
        assert!(!saida.contains("999999"), "o OTP vazou: {saida}");
        // O que não é segredo continua legível, senão o log não serve.
        assert!(saida.contains("DC"));
    }

    #[test]
    fn token_vira_impressao_digital_estavel() {
        let d = Diag::inerte();
        let a = d.redigir(&serde_json::json!({"token": "sessaoAssinatura;327989;..."}));
        let b = d.redigir(&serde_json::json!({"token": "sessaoAssinatura;327989;..."}));
        let c = d.redigir(&serde_json::json!({"token": "outro"}));
        assert_eq!(a, b, "o mesmo token tem de dar a mesma impressão digital");
        assert_ne!(a, c, "tokens diferentes têm de se distinguir no log");
        assert!(!a.to_string().contains("327989"));
        assert!(a.to_string().contains("sha256="));
    }

    #[test]
    fn redige_dentro_de_estruturas_aninhadas() {
        let d = Diag::inerte();
        let v = serde_json::json!({"request": {"body": {"senha": "s3cr3t"}}});
        assert!(!d.redigir(&v).to_string().contains("s3cr3t"));
    }

    #[test]
    fn distingue_campo_vazio_de_ausente() {
        // A diferença importa: foi ela que o harness usou para provar que o
        // servidor cobrava o fator, e não o formato do JSON.
        let d = Diag::inerte();
        let vazio = d.redigir(&serde_json::json!({"otp": ""}));
        let nulo = d.redigir(&serde_json::json!({"otp": null}));
        assert!(vazio.to_string().contains("<vazio>"));
        assert!(nulo.to_string().contains("<ausente>"));
    }

    #[test]
    fn poda_mantendo_os_mais_recentes() {
        let dir = std::env::temp_dir().join(format!("dtid-poda-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for i in 0..5 {
            fs::write(dir.join(format!("run-100000000{i}-1.jsonl")), b"x").unwrap();
        }
        fs::write(dir.join("outro.txt"), b"x").unwrap();
        podar(&dir, 2);
        let restantes: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(restantes.iter().filter(|n| n.starts_with("run-")).count(), 2);
        assert!(restantes.contains(&"run-1000000004-1.jsonl".to_string()));
        // Arquivo que não é de execução não é tocado.
        assert!(restantes.contains(&"outro.txt".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }
}
