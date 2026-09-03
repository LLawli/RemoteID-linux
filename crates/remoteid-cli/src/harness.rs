//! O harness: roda o fluxo inteiro com uma conta real e gera um relatório.
//!
//! É a ferramenta que um testador executa. A diferença para o `preparar` +
//! `assinar` do uso normal é o propósito: aqui nenhuma falha aborta o programa.
//! Cada etapa é classificada, o motivo é registrado, e o que dependia da etapa
//! quebrada é marcado como pulado. Um relatório que diz "parou aqui, o servidor
//! respondeu isto" vale mais que um `exit 1`.
//!
//! # Sobre o que vai no relatório
//!
//! O arquivo é feito para ser ENVIADO por um canal privado, então ele reusa a
//! redação do log de diagnóstico: senha, PIN e OTP nunca aparecem, e tokens
//! saem como impressão digital. As versões anteriores deste harness, em Python,
//! mandavam o `sessionToken` e o certificado em texto claro porque o protocolo
//! ainda estava sendo descoberto e era preciso inspecionar os valores. Isso não
//! é mais necessário: o fluxo fechou, e o que se quer saber agora é ONDE
//! quebrou, não QUAL era o token.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use remoteid_core::authmode::Fatores;
use remoteid_core::crypto::sha256;
use remoteid_core::diag::iso8601;
use remoteid_core::error::Origem;
use remoteid_core::Motor;

/// Conteúdo assinado no teste. Fixo, para o relatório ser comparável entre runs.
const MENSAGEM_TESTE: &[u8] = b"RemoteID-linux harness teste";

#[derive(Clone, Copy, PartialEq)]
enum Marca {
    Ok,
    Falha,
    Pulado,
    NaoAplica,
}

impl Marca {
    fn simbolo(self) -> &'static str {
        match self {
            Marca::Ok => "[OK]",
            Marca::Falha => "[XX]",
            Marca::Pulado => "[  ]",
            Marca::NaoAplica => "[--]",
        }
    }
}

struct Passo {
    rotulo: String,
    marca: Marca,
    detalhe: String,
}

pub struct Harness {
    motor: Motor,
    passos: Vec<Passo>,
    diario: Vec<String>,
    inicio: u64,
}

impl Harness {
    pub fn novo(motor: Motor) -> Harness {
        Harness {
            motor,
            passos: Vec::new(),
            diario: Vec::new(),
            inicio: agora(),
        }
    }

    // --- registro ---------------------------------------------------------

    fn passo(&mut self, rotulo: &str, marca: Marca, detalhe: impl Into<String>) {
        let detalhe = detalhe.into();
        println!("  {} {rotulo}{}", marca.simbolo(), sufixo(&detalhe));
        self.passos.push(Passo { rotulo: rotulo.into(), marca, detalhe });
    }

    fn nota(&mut self, linha: impl Into<String>) {
        self.diario.push(linha.into());
    }

    /// Registra uma falha já classificada pela origem, que é o que evita o
    /// testador perder tempo conferindo credencial quando o defeito é nosso.
    fn falha(&mut self, rotulo: &str, erro: &remoteid_core::Error) {
        let origem = match erro.origem() {
            Origem::Usuario => " (dado seu)",
            Origem::Cliente => " (defeito deste cliente)",
            Origem::Servidor => " (servidor da Certisign)",
            Origem::Desconhecida => "",
        };
        let detalhe = format!("{erro}{origem}");
        self.nota(format!("FALHA em {rotulo}: {detalhe}"));
        self.passo(rotulo, Marca::Falha, detalhe);
    }

    // --- etapas -----------------------------------------------------------

    pub fn rodar(&mut self, ctx: &super::Args) {
        println!("\n== RemoteID-linux — validação do protocolo ==\n");
        self.etapa_ambiente();
        self.etapa_conectividade();
        if !self.etapa_login(ctx) {
            self.pular_resto("sem login não há o que testar adiante");
            return;
        }
        if !self.etapa_registrar(ctx) {
            self.pular_resto("sem codigoDesktop os passos seguintes não se aplicam");
            return;
        }
        self.etapa_status_celular();
        if !self.etapa_carteira() {
            self.passo("assinatura", Marca::Pulado, "sem certificado da carteira");
            return;
        }
        self.etapa_assinar(ctx);
    }

    fn etapa_ambiente(&mut self) {
        let modo = self.motor.estado.auth_mode.clone();
        self.nota(format!("início   : {}", iso8601(self.inicio)));
        self.nota(format!("versão   : {}", env!("CARGO_PKG_VERSION")));
        self.nota(format!(
            "sistema  : {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
        self.nota(format!("modo     : {modo} (política local)"));
        // A chave da instalação é criada por Motor::abrir; se chegamos aqui,
        // ela existe. Registrar isso separa "não gerou chave" de "não registrou".
        self.passo("chave da instalação", Marca::Ok, "RSA-2048 pronta");
    }

    fn etapa_conectividade(&mut self) {
        match self.motor.hierarquias() {
            Ok(v) => {
                let n = v
                    .get("hierarchies")
                    .and_then(|h| h.as_array())
                    .map_or(0, |a| a.len());
                self.passo("conectividade", Marca::Ok, format!("{n} hierarquias"));
            }
            Err(e) => self.falha("conectividade", &e),
        }
    }

    fn etapa_login(&mut self, ctx: &super::Args) -> bool {
        let email = match ctx.texto("email", "REMOTEID_EMAIL", "e-mail do RemoteID") {
            Ok(v) => v,
            Err(e) => {
                self.passo("login", Marca::Falha, e);
                return false;
            }
        };
        let senha = match ctx.segredo("senha", "REMOTEID_SENHA", "senha do RemoteID") {
            Ok(v) => v,
            Err(e) => {
                self.passo("login", Marca::Falha, e);
                return false;
            }
        };
        match self.motor.login(&email, &senha) {
            Ok(()) => {
                let e = &self.motor.estado;
                let quem = e.nome.clone().unwrap_or_default();
                let uid = e.user_id.unwrap_or_default();
                let oid = e.organizacao_id.unwrap_or_default();
                self.nota(format!("login    : userId={uid} organizacaoId={oid}"));
                self.passo("login RemoteID", Marca::Ok, quem);
                let _ = self.motor.salvar_estado();
                true
            }
            Err(e) => {
                self.falha("login RemoteID", &e);
                false
            }
        }
    }

    fn etapa_registrar(&mut self, ctx: &super::Args) -> bool {
        let nome = ctx.opcao("nome").unwrap_or_else(super::nome_padrao);
        match self.motor.registrar(&nome) {
            Ok(codigo) => {
                self.nota(format!("registro : nomeDesktop={nome}"));
                self.passo("registrar desktop", Marca::Ok, codigo);
                let _ = self.motor.salvar_estado();
                true
            }
            Err(e) => {
                self.falha("registrar desktop", &e);
                false
            }
        }
    }

    fn etapa_status_celular(&mut self) {
        match self.motor.status_celular() {
            Ok(tem) => {
                self.passo(
                    "statusCelular",
                    Marca::Ok,
                    format!("celular pareado: {}", se(tem)),
                );
                // Registrar que este valor NÃO decide nada evita que a próxima
                // pessoa a ler o relatório conclua que a conta "está em push".
                self.nota(
                    "statusCelular: informativo. O app oficial lê este booleano e \
                     grava o modo como `local` de qualquer jeito."
                        .to_string(),
                );
                let _ = self.motor.salvar_estado();
            }
            Err(e) => self.falha("statusCelular", &e),
        }
    }

    fn etapa_carteira(&mut self) -> bool {
        match self.motor.carteira() {
            Ok(certs) => {
                let resumo: Vec<String> = certs
                    .iter()
                    .map(|c| format!("serial {} / {}", c.serial_number, c.issue))
                    .collect();
                for r in &resumo {
                    self.diario.push(format!("cert     : {r}"));
                }
                let n = resumo.len();
                self.passo("carteira", Marca::Ok, format!("{n} certificado(s)"));
                let _ = self.motor.salvar_estado();
                true
            }
            Err(e) => {
                self.falha("carteira", &e);
                false
            }
        }
    }

    fn etapa_assinar(&mut self, ctx: &super::Args) {
        use remoteid_core::EstadoAuth;
        let modo = self.motor.estado.modo();

        let fatores = match modo.estado() {
            EstadoAuth::PromptForPush => {
                println!("  modo `push`: aprove no celular quando o pedido chegar.");
                Fatores::Push
            }
            EstadoAuth::MobileId => {
                self.passo(
                    "assinatura",
                    Marca::NaoAplica,
                    "modo mobileId não passa pelo RemoteID",
                );
                return;
            }
            EstadoAuth::Interativo => {
                println!(
                    "\n  O PIN é o do CERTIFICADO em nuvem (definido na emissão/ativação),\n  \
                     não a senha do portal nem o código do autenticador."
                );
                let pin = match ctx.segredo("pin", "REMOTEID_PIN", "PIN do certificado") {
                    Ok(v) => v,
                    Err(e) => {
                        self.passo("assinatura", Marca::Pulado, e);
                        return;
                    }
                };
                println!(
                    "\n  Agora gere o código no autenticador. Ele é de uso único e vale\n  \
                     poucos segundos: gere AGORA, não antes."
                );
                let otp = match ctx.segredo("otp", "REMOTEID_OTP", "código do autenticador (OTP)")
                {
                    Ok(v) => v,
                    Err(e) => {
                        self.passo("assinatura", Marca::Pulado, e);
                        return;
                    }
                };
                // O diagnóstico do que foi digitado, sem gravar o valor: é o
                // que distingue "OTP errado" de "OTP com espaço colado junto".
                self.nota(format!(
                    "otp digitado: {} caracteres, não-dígitos: {}",
                    otp.chars().count(),
                    match otp.chars().filter(|c| !c.is_ascii_digit()).count() {
                        0 => "nenhum".to_string(),
                        n => n.to_string(),
                    }
                ));
                Fatores::PinOtp { pin, otp }
            }
        };

        let digest = sha256(MENSAGEM_TESTE);
        self.nota(format!(
            "assinado : sha256(\"{}\")",
            String::from_utf8_lossy(MENSAGEM_TESTE)
        ));
        match self.motor.assinar_digest(&digest, &fatores) {
            Ok(assinatura) => {
                // O tamanho é a informação que importa: 256 bytes confirmam
                // RSA-2048 cru, e não um PKCS#7 já montado.
                self.passo(
                    "assinatura",
                    Marca::Ok,
                    format!("{} bytes (RSA-2048 cru)", assinatura.len()),
                );
                let confere = verificar_com_o_certificado(&self.motor, &digest, &assinatura);
                self.passo(
                    "assinatura confere com o certificado",
                    if confere == Some(true) { Marca::Ok } else { Marca::Falha },
                    match confere {
                        Some(true) => "verificada com a chave pública do titular".into(),
                        Some(false) => "NÃO confere — o HSM assinou outra coisa".to_string(),
                        None => "não verificada (certificado não veio na carteira)".to_string(),
                    },
                );
            }
            Err(e) => self.falha("assinatura", &e),
        }
    }

    fn pular_resto(&mut self, motivo: &str) {
        for r in ["registrar desktop", "statusCelular", "carteira", "assinatura"] {
            if !self.passos.iter().any(|p| p.rotulo == r) {
                self.passo(r, Marca::Pulado, motivo);
            }
        }
    }

    // --- relatório --------------------------------------------------------

    pub fn salvar(&self) -> std::io::Result<PathBuf> {
        let caminho = destino(self.inicio);
        if let Some(pai) = caminho.parent() {
            std::fs::create_dir_all(pai)?;
        }
        escrever_privado(&caminho, self.render().as_bytes())?;
        Ok(caminho)
    }

    fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "==============================================================================\n\
             RemoteID-linux — validação do protocolo RemoteID\n\
             =============================================================================="
        );
        let _ = writeln!(
            s,
            "\nEste arquivo mostra ONDE o fluxo parou, com a resposta do servidor em cada\n\
             etapa. Senha, PIN e OTP não são gravados; tokens aparecem só como impressão\n\
             digital. Mesmo assim ele identifica o titular do certificado: trate como\n\
             material privado e envie por canal fechado."
        );

        let _ = writeln!(s, "\n------------------------------------------------------------------------------");
        let _ = writeln!(s, "RESUMO");
        let _ = writeln!(s, "------------------------------------------------------------------------------");
        for p in &self.passos {
            let _ = writeln!(s, "{} {}", p.marca.simbolo(), p.rotulo);
            if !p.detalhe.is_empty() {
                let _ = writeln!(s, "       {}", p.detalhe);
            }
        }
        let falhou = self.passos.iter().filter(|p| p.marca == Marca::Falha).count();
        let _ = writeln!(
            s,
            "\nresultado: {}",
            if falhou == 0 {
                "todas as etapas executadas passaram".to_string()
            } else {
                format!("{falhou} etapa(s) falharam")
            }
        );

        let _ = writeln!(s, "\n------------------------------------------------------------------------------");
        let _ = writeln!(s, "DIÁRIO");
        let _ = writeln!(s, "------------------------------------------------------------------------------");
        for l in &self.diario {
            let _ = writeln!(s, "{l}");
        }

        let _ = writeln!(s, "\n------------------------------------------------------------------------------");
        let _ = writeln!(s, "TRANSCRIÇÃO HTTP (uma linha JSON por evento, já redigida)");
        let _ = writeln!(s, "------------------------------------------------------------------------------");
        match self.motor.caminho_diag().map(std::fs::read_to_string) {
            Some(Ok(conteudo)) => s.push_str(&conteudo),
            _ => {
                let _ = writeln!(s, "(o log de diagnóstico desta execução não pôde ser lido)");
            }
        }
        s
    }
}

/// Confere a assinatura do HSM contra a chave pública do certificado da carteira.
///
/// É a verificação que fecha o teste: sem ela, "recebi 256 bytes" só prova que o
/// servidor respondeu algo do tamanho certo. `None` quando a carteira não trouxe
/// o certificado, para não confundir "não deu para verificar" com "não confere".
fn verificar_com_o_certificado(motor: &Motor, digest: &[u8], assinatura: &[u8]) -> Option<bool> {
    let cert = motor.estado.certificado().ok()?;
    let der = remoteid_core::crypto::de_b64(cert.base64.as_deref()?).ok()?;
    // `ok()` colapsa o erro de parse em "não deu para verificar", que é o que
    // o relatório precisa distinguir de "não confere".
    remoteid_core::crypto::verificar_com_certificado(&der, digest, assinatura).ok()
}

fn se(v: bool) -> &'static str {
    if v {
        "sim"
    } else {
        "não"
    }
}

fn sufixo(detalhe: &str) -> String {
    if detalhe.is_empty() {
        String::new()
    } else {
        format!(" — {detalhe}")
    }
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `~/Downloads` quando existe, senão `$HOME`, senão o diretório atual.
fn destino(inicio: u64) -> PathBuf {
    // 2026-09-03T11:47:39Z -> 20260903-114739
    let t = iso8601(inicio);
    let carimbo: String = t
        .trim_end_matches('Z')
        .replace('T', "-")
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let nome = format!("remoteid-harness-{carimbo}.txt");

    if let Ok(home) = std::env::var("HOME") {
        let downloads = Path::new(&home).join("Downloads");
        if downloads.is_dir() {
            return downloads.join(nome);
        }
        return Path::new(&home).join(nome);
    }
    PathBuf::from(nome)
}

/// 0600 desde a criação: o relatório identifica o titular do certificado.
fn escrever_privado(caminho: &Path, conteudo: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(caminho)?;
    f.write_all(conteudo)?;
    f.sync_all()
}
