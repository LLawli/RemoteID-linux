//! Os subcomandos de terminal.

use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use flate2::Compression;
use flate2::write::GzEncoder;
use remoteid::cades;
use remoteid::caminhos::{self, Caminhos};
use remoteid::cofre;
use remoteid::cripto::{de_b64, de_hex};
use remoteid::diagnostico::{self, Diagnostico};
use remoteid::estado::Estado;
use remoteid::harness;
use remoteid::motor::{Autorizador, Credencial, Erro, Fatores, Motor};
use remoteid::pedido::Dialogo;
use remoteid::pin;
use remoteid::protocolo::requisicao::Maquina;
use remoteid::protocolo::{Algoritmo, Certificado};
use remoteid::servico;
use remoteid::transporte::{Http, TEMPO_LIMITE};
use remoteid::x509;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const ENTRAR: &str = "entrar";
pub const ASSINAR: &str = "assinar";
pub const HARNESS: &str = "harness";
pub const DIAGNOSTICO: &str = "diagnostico";
pub const ESTADO: &str = "estado";
pub const ATUALIZAR: &str = "atualizar";
pub const USAR: &str = "usar";
pub const REAUTORIZAR: &str = "reautorizar";
pub const SAIR: &str = "sair";
pub const SERVIR: &str = "servir";
pub const AJUDA: &str = "ajuda";

const USO: &str = "\
uso: remoteid <comando>

  entrar <email>       entra na conta e registra esta máquina (senha pelo stdin)
  estado [--json]      a conta e os certificados, sem ir à rede
  atualizar            baixa de novo a carteira
  usar <chave|série>   escolhe o certificado que assina
  assinar [--ajuda]    assina o stdin; --ajuda mostra as opções
  reautorizar          a próxima assinatura pede o código de novo
  sair                 sai da conta neste computador
  servir [--socket <caminho>]
                       a API em JSON por linha, no stdin e stdout ou num socket
  harness              testa o fluxo inteiro e grava um relatório
  diagnostico          os registros, num .tar.gz pelo stdout";

const USO_DIAGNOSTICO: &str = "uso: remoteid diagnostico > remoteid-diagnostico.tar.gz";

/// A pasta dentro do pacote, para o pacote não se espalhar ao ser aberto.
const PASTA_DO_PACOTE: &str = "remoteid-diagnostico";

const USO_ASSINAR: &str = "\
uso: remoteid assinar [--anexar | --cru] [--hash <hex>] [--certificado <chave|série>]
                       < documento > saída

  sem opção     .p7s destacado do documento, na política AD-RB da ICP-Brasil
  --anexar      .p7s com o documento dentro
  --cru         a assinatura RSA (PKCS#1 v1.5, SHA-256) sem envelope
  --hash <hex>  assina este SHA-256 em vez de ler o documento
  --certificado <chave|série>
                assina com este certificado em vez do ativo

O código do autenticador é pedido no terminal ou, sem terminal, numa janela.";

/// O motor de quem roda no terminal, com o chaveiro e o diagnóstico. Devolve
/// também o arquivo de diagnóstico desta execução.
fn abrir_motor(comando: &str) -> Result<(Motor, Caminhos, Option<PathBuf>), Erro> {
    let caminhos = Caminhos::do_ambiente();
    let diagnostico = Diagnostico::abrir(&caminhos.diagnostico(), &format!("terminal {comando}"));
    let arquivo = diagnostico.caminho().map(PathBuf::from);
    let motor = Motor::abrir(
        caminhos.clone(),
        caminhos::servidor(),
        Box::new(Http::novo(TEMPO_LIMITE)),
    )?
    .com_cofre(cofre::do_ambiente())
    .com_diagnostico(diagnostico);
    Ok((motor, caminhos, arquivo))
}

/// Fecha a memória do processo, onde a senha, o PIN e o OTP passam em
/// claro: sem core dump numa queda, e sem `ptrace` nem `/proc/<pid>/mem`
/// para outro processo do mesmo usuário. Tem de rodar no próprio processo:
/// o `execve` volta o `dumpable` para 1.
pub fn proteger_processo() -> io::Result<()> {
    let sem_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit só lê a struct, que vive até o fim da chamada.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &sem_core) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: prctl com PR_SET_DUMPABLE só lê o segundo argumento.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn falhar(mensagem: impl std::fmt::Display, diagnostico: Option<&PathBuf>) -> ExitCode {
    eprintln!("remoteid: {mensagem}");
    if let Some(d) = diagnostico {
        eprintln!("detalhes em {}", d.display());
    }
    ExitCode::FAILURE
}

/// `remoteid entrar <email>`: entra na conta, registra esta máquina e baixa a
/// carteira. A senha vem pelo stdin, nunca por argumento. Sem chaveiro no
/// sistema, a segunda linha é o PIN local que vai proteger a senha
/// ([`remoteid::pin`]); sem ela, a senha é pedida a cada sessão.
pub fn entrar(args: &[String]) -> ExitCode {
    let [email] = args else {
        eprintln!(
            "uso: remoteid entrar <email>  (senha pelo stdin; sem chaveiro, o PIN na linha seguinte)"
        );
        return ExitCode::FAILURE;
    };
    let mut entrada = std::io::stdin().lock();
    let mut senha = Zeroizing::new(String::new());
    if entrada.read_line(&mut senha).is_err() {
        return ExitCode::FAILURE;
    }
    let senha = senha.trim_end_matches(['\r', '\n']);
    let (maquina_nome, usuario) = remoteid::desta_maquina();
    let maquina = Maquina {
        nome: &maquina_nome,
        usuario_local: &usuario,
        dominio_rede: &maquina_nome,
    };
    let (mut motor, _, diagnostico) = match abrir_motor(ENTRAR) {
        Ok(m) => m,
        Err(e) => return falhar(e, None),
    };
    match motor.preparar(email, senha, &maquina) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            let mut pin = Zeroizing::new(String::new());
            let _ = entrada.read_line(&mut pin);
            let pin = pin.trim();
            if !pin::valido(pin) {
                eprintln!(
                    "sem chaveiro no sistema e sem um PIN de {} a {} dígitos: a senha será pedida a cada sessão",
                    pin::MIN_DIGITOS,
                    pin::MAX_DIGITOS
                );
                return ExitCode::SUCCESS;
            }
            match motor.proteger_com_pin(senha, pin) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => falhar(e, diagnostico.as_ref()),
            }
        }
        Err(e) => falhar(e, diagnostico.as_ref()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Saida {
    Destacado,
    Anexado,
    Cru,
}

/// O que a linha de comando do `assinar` pediu.
#[derive(Debug, PartialEq, Eq)]
struct Pedido {
    saida: Saida,
    hash: Option<[u8; 32]>,
    certificado: Option<String>,
}

fn analisar(args: &[String]) -> Result<Pedido, String> {
    let mut saida = Saida::Destacado;
    let mut hash = None;
    let mut certificado = None;
    let mut resto = args.iter();
    while let Some(arg) = resto.next() {
        match arg.as_str() {
            "--anexar" | "--cru" if saida != Saida::Destacado => {
                return Err("--anexar e --cru não vão juntos".into());
            }
            "--anexar" => saida = Saida::Anexado,
            "--cru" => saida = Saida::Cru,
            "--hash" => {
                let hex = resto
                    .next()
                    .ok_or("--hash precisa do SHA-256 em hexadecimal")?;
                hash = Some(de_hex(hex).ok_or("--hash quer 64 dígitos hexadecimais (SHA-256)")?);
            }
            "--certificado" => {
                let c = resto
                    .next()
                    .ok_or("--certificado precisa da chave ou da série")?;
                certificado = Some(c.clone());
            }
            outro => return Err(format!("opção desconhecida: {outro}")),
        }
    }
    if saida == Saida::Anexado && hash.is_some() {
        return Err("--anexar precisa do documento, e --hash é só o resumo".into());
    }
    Ok(Pedido {
        saida,
        hash,
        certificado,
    })
}

/// `remoteid assinar`: o documento entra pelo stdin e a assinatura sai pelo
/// stdout, porque o sandbox do Âncora não enxerga a pasta pessoal.
pub fn assinar(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--ajuda") {
        println!("{USO_ASSINAR}");
        return ExitCode::SUCCESS;
    }
    let pedido = match analisar(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("remoteid: {e}\n\n{USO_ASSINAR}");
            return ExitCode::FAILURE;
        }
    };
    let mut saida = std::io::stdout().lock();
    if saida.is_terminal() {
        eprintln!("remoteid: a assinatura é binária; redirecione a saída\n\n{USO_ASSINAR}");
        return ExitCode::FAILURE;
    }
    let (digest, conteudo) = match ler_documento(&pedido) {
        Ok(d) => d,
        Err(e) => return falhar(format!("não leu o documento: {e}"), None),
    };
    let Some(autorizador) = autorizador() else {
        return falhar(
            "sem terminal nem janela para pedir o código do autenticador",
            None,
        );
    };
    let (mut motor, _, diagnostico) = match abrir_motor(ASSINAR) {
        Ok(m) => m,
        Err(e) => return falhar(e, None),
    };
    let certificado = match &pedido.certificado {
        Some(c) => servico::achar(&motor.estado, c).cloned(),
        None => motor.estado.certificado().cloned(),
    };
    let Some(certificado) = certificado else {
        return falhar("o certificado não está na carteira", None);
    };
    let resultado = match pedido.saida {
        Saida::Cru => motor.assinar_com(
            &certificado,
            Algoritmo::Sha256,
            &digest,
            autorizador.as_ref(),
        ),
        _ => cades::assinar_com(
            &mut motor,
            &certificado,
            &digest,
            conteudo,
            agora(),
            autorizador.as_ref(),
        ),
    };
    let bytes = match resultado {
        Ok(b) => b,
        Err(e) => return falhar(e, diagnostico.as_ref()),
    };
    if let Err(e) = saida.write_all(&bytes).and_then(|()| saida.flush()) {
        return falhar(format!("não escreveu a assinatura: {e}"), None);
    }
    let tipo = match pedido.saida {
        Saida::Destacado => ".p7s destacado",
        Saida::Anexado => ".p7s anexado",
        Saida::Cru => "assinatura crua",
    };
    eprintln!("{tipo}, {} bytes", bytes.len());
    ExitCode::SUCCESS
}

/// O SHA-256 do documento, e o documento inteiro só quando ele vai anexado.
fn ler_documento(pedido: &Pedido) -> std::io::Result<([u8; 32], Option<Vec<u8>>)> {
    if let Some(hash) = pedido.hash {
        return Ok((hash, None));
    }
    let mut entrada = std::io::stdin().lock();
    if pedido.saida == Saida::Anexado {
        let mut bytes = Vec::new();
        entrada.read_to_end(&mut bytes)?;
        return Ok((Sha256::digest(&bytes).into(), Some(bytes)));
    }
    let mut hasher = Sha256::new();
    std::io::copy(&mut entrada, &mut hasher)?;
    Ok((hasher.finalize().into(), None))
}

/// `remoteid harness`: o fluxo com a conta já entrada, e um relatório para
/// enviar.
pub fn harness(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("uso: remoteid harness");
        return ExitCode::FAILURE;
    }
    let Some(autorizador) = autorizador() else {
        return falhar(
            "sem terminal nem janela para pedir o código do autenticador",
            None,
        );
    };
    let (mut motor, caminhos, diagnostico) = match abrir_motor(HARNESS) {
        Ok(m) => m,
        Err(e) => return falhar(e, None),
    };
    let relatorio = harness::rodar(
        &mut motor,
        autorizador.as_ref(),
        agora(),
        diagnostico,
        |passo| println!("{passo}"),
    );
    match relatorio.salvar(&caminhos.diagnostico()) {
        Ok(caminho) => println!(
            "\nrelatório: {}\nEnvie por um canal privado: não traz senha, PIN, OTP nem o titular,\n\
             mas o diagnóstico ao lado identifica a conta.",
            caminho.display()
        ),
        Err(e) => eprintln!("remoteid: não gravou o relatório: {e}"),
    }
    if relatorio.falhou() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `remoteid diagnostico > arquivo.tar.gz`: os registros desta conta e o
/// ambiente, num pacote para anexar a um relato de erro. Sai pela saída
/// padrão porque o hospedeiro não enxerga a pasta pessoal.
pub fn diagnostico(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("{USO_DIAGNOSTICO}");
        return ExitCode::FAILURE;
    }
    let saida = io::stdout();
    if saida.is_terminal() {
        eprintln!("remoteid: o pacote é binário, mande a saída para um arquivo\n{USO_DIAGNOSTICO}");
        return ExitCode::FAILURE;
    }
    match empacotar(&Caminhos::do_ambiente().diagnostico(), saida.lock()) {
        Ok(n) => {
            eprintln!(
                "{n} registros no pacote. Envie por um canal privado: não traz senha, PIN,\n\
                 OTP nem o titular, mas identifica a conta."
            );
            ExitCode::SUCCESS
        }
        Err(e) => falhar(format!("não montou o pacote: {e}"), None),
    }
}

/// Grava em `saida` o `.tar.gz` com o ambiente e cada arquivo de `pasta`.
/// Devolve quantos arquivos foram.
fn empacotar(pasta: &Path, saida: impl Write) -> io::Result<usize> {
    let mut arquivos: Vec<PathBuf> = match fs::read_dir(pasta) {
        Ok(entradas) => entradas
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    arquivos.sort();
    let nome = |p: &Path| {
        p.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };

    let mut ambiente = diagnostico::ambiente();
    ambiente["gerado"] = agora().into();
    ambiente["arquivos"] = arquivos
        .iter()
        .map(|p| serde_json::json!({"nome": nome(p), "bytes": p.metadata().map_or(0, |m| m.len())}))
        .collect();
    let mut pacote = tar::Builder::new(GzEncoder::new(saida, Compression::default()));
    let texto = serde_json::to_vec_pretty(&ambiente).map_err(io::Error::other)?;
    acrescentar(&mut pacote, "ambiente.json", &texto, agora())?;
    for arquivo in &arquivos {
        // Um navegador aberto pode estar gravando: entra o que havia agora.
        let dados = fs::read(arquivo)?;
        let quando = fs::metadata(arquivo)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        acrescentar(&mut pacote, &nome(arquivo), &dados, quando)?;
    }
    pacote.into_inner()?.finish()?.flush()?;
    Ok(arquivos.len())
}

fn acrescentar<W: Write>(
    pacote: &mut tar::Builder<W>,
    nome: &str,
    dados: &[u8],
    quando: u64,
) -> io::Result<()> {
    let mut cabecalho = tar::Header::new_gnu();
    cabecalho.set_size(dados.len() as u64);
    cabecalho.set_mode(0o600);
    cabecalho.set_mtime(quando);
    cabecalho.set_cksum();
    pacote.append_data(&mut cabecalho, format!("{PASTA_DO_PACOTE}/{nome}"), dados)
}

pub fn ajuda() -> ExitCode {
    println!("{USO}");
    ExitCode::SUCCESS
}

/// Recusa argumentos que o comando não aceita.
fn sem_argumentos(args: &[String], uso: &str) -> Result<(), ExitCode> {
    if args.is_empty() {
        Ok(())
    } else {
        eprintln!("uso: remoteid {uso}");
        Err(ExitCode::FAILURE)
    }
}

/// Roda `op` num motor do terminal.
fn com_motor(comando: &str, op: impl FnOnce(&mut Motor) -> Result<(), Erro>) -> ExitCode {
    let (mut motor, _, diagnostico) = match abrir_motor(comando) {
        Ok(m) => m,
        Err(e) => return falhar(e, None),
    };
    match op(&mut motor) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => falhar(e, diagnostico.as_ref()),
    }
}

/// `remoteid estado [--json]`: a conta e os certificados, como a janela os
/// mostra, sem ir à rede.
pub fn estado(args: &[String]) -> ExitCode {
    let json = match args {
        [] => false,
        [a] if a == "--json" => true,
        _ => {
            eprintln!("uso: remoteid estado [--json]");
            return ExitCode::FAILURE;
        }
    };
    let estado = match Estado::carregar(&Caminhos::do_ambiente().estado()) {
        Ok(e) => e,
        Err(e) => return falhar(Erro::Disco(e), None),
    };
    let visao = servico::visao(&estado, agora());
    if json {
        println!("{visao}");
    } else {
        print!("{}", em_texto(&visao));
    }
    ExitCode::SUCCESS
}

/// A [`servico::visao`] para gente ler.
fn em_texto(visao: &serde_json::Value) -> String {
    let texto = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
    let Some(conta) = visao["conta"].as_object() else {
        return "fora da conta: remoteid entrar <email>\n".into();
    };
    let mut saida = format!("conta       {}\n", texto(&conta["email"]));
    if let Some(computador) = visao["computador"].as_str() {
        saida += &format!("computador  {computador}\n");
    }
    if let Some(pareado) = visao["celular_pareado"].as_bool() {
        saida += &format!(
            "celular     {}\n",
            if pareado { "pareado" } else { "sem celular" }
        );
    }
    for c in visao["certificados"].as_array().into_iter().flatten() {
        let marca = if c["ativo"] == true { "*" } else { " " };
        saida += &format!("\n{marca} {}\n", texto(&c["titular"]));
        if let Some(documento) = c["documento"].as_str() {
            saida += &format!("  {} {documento}\n", texto(&c["tipo"]));
        }
        saida += &format!("  emissor   {}\n", texto(&c["emissor"]));
        saida += &format!("  série     {}\n", texto(&c["serie"]));
        if let Some(dias) = c["dias_restantes"].as_i64() {
            saida += &format!("  validade  {dias} dias\n");
        }
        let sessao = if c["sessao"]["aberta"] == true {
            "aberta: a próxima assinatura não pede código"
        } else {
            "fechada: a próxima assinatura pede o código"
        };
        saida += &format!("  sessão    {sessao}\n");
    }
    saida
}

/// `remoteid atualizar`: baixa de novo a carteira e o estado do celular.
pub fn atualizar(args: &[String]) -> ExitCode {
    if let Err(c) = sem_argumentos(args, ATUALIZAR) {
        return c;
    }
    com_motor(ATUALIZAR, |m| {
        let _ = m.atualizar_celular();
        m.atualizar_carteira()
    })
}

/// `remoteid usar <chave|série>`: escolhe o certificado que assina.
pub fn usar(args: &[String]) -> ExitCode {
    let [certificado] = args else {
        eprintln!("uso: remoteid usar <chave|série>  (veja remoteid estado)");
        return ExitCode::FAILURE;
    };
    com_motor(USAR, |m| {
        let chave = servico::achar(&m.estado, certificado)
            .map(Certificado::chave)
            .ok_or(Erro::NaoPreparado("o certificado não está na carteira"))?;
        m.escolher_certificado(&chave)
    })
}

/// `remoteid reautorizar`: a próxima assinatura pede o código de novo.
pub fn reautorizar(args: &[String]) -> ExitCode {
    if let Err(c) = sem_argumentos(args, REAUTORIZAR) {
        return c;
    }
    com_motor(REAUTORIZAR, Motor::reautorizar_proxima)
}

/// `remoteid sair`: esquece a conta, a carteira e a senha neste computador.
pub fn sair(args: &[String]) -> ExitCode {
    if let Err(c) = sem_argumentos(args, SAIR) {
        return c;
    }
    com_motor(SAIR, Motor::sair)
}

/// `remoteid servir`: a API de [`servico`], no stdin e stdout ou, com
/// `--socket`, num socket Unix só do usuário, uma conversa por conexão.
pub fn servir(args: &[String]) -> ExitCode {
    let motor = || abrir_motor(SERVIR).map(|(m, _, _)| m);
    match args {
        [] => {
            servico::atender(motor(), io::stdin().lock(), io::stdout().lock());
            ExitCode::SUCCESS
        }
        [opcao, caminho] if opcao == "--socket" => match ouvir(Path::new(caminho)) {
            Ok(ouvinte) => {
                eprintln!("remoteid: servindo em {caminho}");
                for conexao in ouvinte.incoming().flatten() {
                    std::thread::spawn(move || {
                        let Ok(leitura) = conexao.try_clone() else {
                            return;
                        };
                        servico::atender(motor(), BufReader::new(leitura), conexao);
                    });
                }
                ExitCode::SUCCESS
            }
            Err(e) => falhar(format!("não abriu o socket {caminho}: {e}"), None),
        },
        _ => {
            eprintln!("uso: remoteid servir [--socket <caminho>]");
            ExitCode::FAILURE
        }
    }
}

/// Abre o socket com permissão só do dono desde o primeiro instante, e
/// troca um socket velho que tenha ficado no caminho. Outro tipo de arquivo
/// ali não é apagado.
fn ouvir(caminho: &Path) -> io::Result<UnixListener> {
    if fs::symlink_metadata(caminho).is_ok_and(|m| m.file_type().is_socket()) {
        fs::remove_file(caminho)?;
    }
    // SAFETY: umask só troca a máscara do processo, devolvida logo abaixo;
    // ainda não há outra thread criando arquivos.
    let antes = unsafe { libc::umask(0o177) };
    let ouvinte = UnixListener::bind(caminho);
    // SAFETY: idem.
    unsafe { libc::umask(antes) };
    ouvinte
}

/// Quem pergunta os fatores: o terminal, ou, sem ele, o diálogo do módulo.
fn autorizador() -> Option<Box<dyn Autorizador>> {
    let dialogo = Dialogo::do_ambiente();
    match File::options().read(true).write(true).open("/dev/tty") {
        Ok(tty) => Some(Box::new(NoTerminal {
            tty,
            dialogo,
            no_fundo: Cell::new(false),
        })),
        Err(_) => dialogo.map(|d| Box::new(d) as Box<dyn Autorizador>),
    }
}

/// Pergunta no `/dev/tty`, sem eco: o stdin e o stdout são do documento e da
/// assinatura.
///
/// O Flatpak 1.18.4 só deixa o app no grupo em primeiro plano do terminal
/// quando stdin, stdout e stderr são todos o terminal; o `assinar`, com a
/// saída redirecionada, fica em segundo plano, e ler ou mexer no terminal dali
/// para o processo com SIGTTIN ou SIGTTOU (medido na VM em 2026-10-31; o 1.18.2
/// não fazia isso). Com os dois ignorados, a leitura volta EIO, e a
/// pergunta vai para o diálogo. Os números de grupo não servem para saber
/// antes: dentro do namespace de PID do sandbox, os dois são 0.
struct NoTerminal {
    tty: File,
    dialogo: Option<Dialogo>,
    /// O terminal já mostrou que não está em primeiro plano.
    no_fundo: Cell<bool>,
}

/// O terminal não está em primeiro plano para este processo.
struct NoFundo;

/// Ignora SIGTTIN e SIGTTOU enquanto vive, e devolve o que havia ao sair.
struct SemParar {
    ttin: libc::sighandler_t,
    ttou: libc::sighandler_t,
}

impl SemParar {
    fn novo() -> SemParar {
        // SAFETY: SIG_IGN não roda código nosso; o anterior volta no drop.
        unsafe {
            SemParar {
                ttin: libc::signal(libc::SIGTTIN, libc::SIG_IGN),
                ttou: libc::signal(libc::SIGTTOU, libc::SIG_IGN),
            }
        }
    }
}

impl Drop for SemParar {
    fn drop(&mut self) {
        // SAFETY: devolve os tratadores que `novo` encontrou.
        unsafe {
            libc::signal(libc::SIGTTIN, self.ttin);
            libc::signal(libc::SIGTTOU, self.ttou);
        }
    }
}

impl NoTerminal {
    /// Uma linha digitada sem eco. `None` é o fim da entrada.
    fn ler_oculto(&self, rotulo: &str) -> Result<Option<Zeroizing<String>>, NoFundo> {
        let mut tty = &self.tty;
        let _ = write!(tty, "{rotulo}: ");
        let fd = self.tty.as_raw_fd();
        // SAFETY: termios é um struct C sem invariantes; tcgetattr o preenche.
        let mut antes: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd é do /dev/tty aberto, e os ponteiros são locais.
        let sem_eco = unsafe { libc::tcgetattr(fd, &mut antes) } == 0 && {
            let mut oculto = antes;
            oculto.c_lflag &= !libc::ECHO;
            // SAFETY: idem.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &oculto) == 0 }
        };
        let mut linha = Zeroizing::new(String::new());
        let lido = BufReader::new(&self.tty).read_line(&mut linha);
        if sem_eco {
            // SAFETY: devolve o estado lido acima ao mesmo fd.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &antes) };
        }
        let _ = writeln!(tty);
        match lido {
            Ok(n) if n > 0 => Ok(Some(Zeroizing::new(
                linha.trim_end_matches(['\r', '\n']).into(),
            ))),
            Err(e) if e.raw_os_error() == Some(libc::EIO) => Err(NoFundo),
            _ => Ok(None),
        }
    }

    fn perguntar(
        &self,
        certificado: &Certificado,
        recusa: Option<&str>,
        credencial: Credencial<'_>,
    ) -> Result<Option<Fatores>, NoFundo> {
        let mut tty = &self.tty;
        let titular = certificado
            .base64
            .as_deref()
            .and_then(de_b64)
            .and_then(|der| x509::ler(&der).ok()?.nome);
        if let Some(titular) = titular {
            let _ = writeln!(tty, "RemoteID: assinar como {titular}");
        }
        if let Some(recusa) = recusa {
            let _ = writeln!(tty, "recusado: {recusa}");
        }
        let (senha, pin) = match credencial {
            Credencial::Guardada => (None, None),
            Credencial::Pin => match self.ler_oculto("PIN local")? {
                Some(pin) => (None, Some(pin)),
                None => return Ok(None),
            },
            Credencial::Senha { atual } => {
                let rotulo = match atual {
                    Some(_) => "Senha da conta (Enter mantém a guardada)",
                    None => "Senha da conta",
                };
                let Some(digitada) = self.ler_oculto(rotulo)? else {
                    return Ok(None);
                };
                match atual {
                    Some(atual) if digitada.is_empty() => {
                        (Some(Zeroizing::new(atual.to_string())), None)
                    }
                    _ => (Some(digitada), None),
                }
            }
        };
        let Some(otp) = self.ler_oculto("Código do autenticador")? else {
            return Ok(None);
        };
        if otp.is_empty() {
            return Ok(None);
        }
        Ok(Some(Fatores {
            senha: senha.map(|s| s.to_string()),
            pin: pin.map(|p| p.to_string()),
            otp: otp.to_string(),
        }))
    }
}

impl Autorizador for NoTerminal {
    fn pedir(
        &self,
        certificado: &Certificado,
        recusa: Option<&str>,
        credencial: Credencial<'_>,
    ) -> Option<Fatores> {
        if !self.no_fundo.get() {
            let sem_parar = SemParar::novo();
            match self.perguntar(certificado, recusa, credencial) {
                Ok(fatores) => return fatores,
                Err(NoFundo) => {
                    self.no_fundo.set(true);
                    let mut tty = &self.tty;
                    let _ = writeln!(tty, "responda na janela do RemoteID");
                    drop(sem_parar);
                }
            }
        }
        self.dialogo
            .as_ref()?
            .pedir(certificado, recusa, credencial)
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

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sem_opcao_e_o_p7s_destacado_do_documento() {
        assert_eq!(
            analisar(&[]),
            Ok(Pedido {
                saida: Saida::Destacado,
                hash: None,
                certificado: None,
            })
        );
    }

    #[test]
    fn hash_em_hexadecimal() {
        let hex = "00ff".repeat(16);
        let p = analisar(&args(&["--cru", "--hash", &hex])).unwrap();
        assert_eq!(p.saida, Saida::Cru);
        assert_eq!(p.hash.unwrap()[..2], [0x00, 0xff]);
        assert!(analisar(&args(&["--hash", "abc"])).is_err());
        assert!(analisar(&args(&["--hash", &"zz".repeat(32)])).is_err());
        assert!(analisar(&args(&["--hash"])).is_err());
    }

    #[test]
    fn combinacoes_que_nao_fazem_sentido_sao_recusadas() {
        let hex = "ab".repeat(32);
        assert!(analisar(&args(&["--anexar", "--cru"])).is_err());
        assert!(analisar(&args(&["--cru", "--anexar"])).is_err());
        assert!(analisar(&args(&["--anexar", "--hash", &hex])).is_err());
        assert!(analisar(&args(&["--p7s"])).is_err());
    }
}
