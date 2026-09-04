//! CLI do motor: o fluxo do RemoteID em comandos, e `assinar` como produto.
//!
//! O parsing de argumentos é feito à mão de propósito. São poucos comandos, e
//! o projeto vale mais sem uma árvore de dependências para um binário que vai
//! acabar embutido num daemon e num módulo PKCS#11.

mod harness;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::Command;

use remoteid_autorizacao::{Fatores, Modo};
use remoteid_cripto::{b64, de_b64, sha256};
use remoteid_tipos::Origem;
use remoteid_assinatura::Montador;
use remoteid_aplicacao::{Motor, Opcoes};

const USO: &str = "\
remoteid — certificado em nuvem RemoteID (Certisign) no Linux

USO
  remoteid <comando> [opções]

COMANDOS
  estado                 mostra o que já está configurado e onde ficam os arquivos
  conectividade          testa o servidor sem precisar de conta
  login                  autentica no RemoteID (guarda userId/organizacaoId)
  registrar              registra este desktop e obtém o codigoDesktop
  carteira               baixa o certificado do titular
  celular                consulta se a conta tem celular pareado para push
  preparar               login + registrar + celular + carteira, em sequência
  harness                roda o fluxo inteiro e gera um relatório para enviar
  assinar                assina um hash com o certificado em nuvem
  modo <valor>           define a política local de autorização
  chave-publica          imprime a chave pública desta instalação (PEM)
  diagnostico            mostra o log detalhado desta e das execuções anteriores

OPÇÕES GERAIS
  --email <e>            e-mail do RemoteID       (ou REMOTEID_EMAIL)
  --senha <s>            senha do RemoteID        (ou REMOTEID_SENHA)
  --pin <p>              PIN do CERTIFICADO       (ou REMOTEID_PIN)
  --otp <o>              código do autenticador   (ou REMOTEID_OTP)
  --nome <n>             nome deste desktop no registro
  --dir <caminho>        diretório de dados (padrão: XDG_DATA_HOME/remoteid-linux)
  --timeout <segundos>   padrão 60
  --remoteid-url <url>   troca a base do RemoteID (homologação/testes)
  --certinext-url <url>  troca a base do serviço certinext
  -h, --help             esta ajuda

OPÇÕES DE `assinar`
  --arquivo <caminho>    assina o SHA-256 do arquivo
  --hash <base64>        assina um digest SHA-256 já pronto, em base64
  --hash-hex <hex>       o mesmo, em hexadecimal
  (sem nenhuma das três, lê o conteúdo da entrada padrão)
  --saida <caminho>      grava a assinatura crua (256 bytes) em vez do base64
  --pkcs7 <caminho>      gera um envelope PKCS#7/CAdES (.p7s) em vez da assinatura
                         crua; destacado por padrão
  --anexar               com --pkcs7, embute o documento dentro do envelope
                         (exige --arquivo)

SEGREDOS
  Passar --pin/--senha na linha de comando deixa o valor visível para qualquer
  processo da máquina (`ps`). Sem a opção, o comando pergunta sem ecoar. Para
  automação, prefira as variáveis de ambiente.

  O OTP é de uso único e vale poucos segundos: gere-o na hora de assinar, não
  antes.
";

fn main() {
    std::process::exit(executar());
}

fn executar() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv[0] == "-h" || argv[0] == "--help" {
        print!("{USO}");
        return 0;
    }
    let args = match Args::analisar(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("erro: {e}");
            return 2;
        }
    };

    match rodar(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("\nerro: {e}");
            // Dizer DE QUEM é o problema evita o usuário conferir credencial
            // quando o defeito é do cliente, e vice-versa.
            match e.origem() {
                Origem::Usuario => eprintln!("      (é um dado seu: confira e refaça)"),
                Origem::Cliente => {
                    eprintln!("      (é um defeito deste cliente, não da sua conta)")
                }
                Origem::Servidor => {
                    eprintln!("      (é do servidor da Certisign; tentar de novo pode resolver)")
                }
                Origem::Desconhecida => {}
            }
            if let Some(p) = args.ultimo_diag.borrow().as_ref() {
                eprintln!("      log detalhado: {}", p.display());
            }
            1
        }
    }
}

// --- argumentos ------------------------------------------------------------

pub struct Args {
    comando: String,
    resto: Vec<String>,
    opcoes: std::collections::HashMap<String, String>,
    /// Preenchido quando o motor abre, para o erro poder citar o log.
    ultimo_diag: std::cell::RefCell<Option<PathBuf>>,
}

impl Args {
    fn analisar(argv: &[String]) -> Result<Args, String> {
        let comando = argv[0].clone();
        let mut opcoes = std::collections::HashMap::new();
        let mut resto = Vec::new();
        let mut i = 1;
        while i < argv.len() {
            let a = &argv[i];
            if let Some(nome) = a.strip_prefix("--") {
                // Aceita tanto `--chave valor` quanto `--chave=valor`.
                if let Some((n, v)) = nome.split_once('=') {
                    opcoes.insert(n.to_string(), v.to_string());
                } else {
                    let valor = argv.get(i + 1).filter(|v| !v.starts_with("--"));
                    match valor {
                        Some(v) => {
                            opcoes.insert(nome.to_string(), v.clone());
                            i += 1;
                        }
                        // Opção sem valor é booleana.
                        None => {
                            opcoes.insert(nome.to_string(), "1".into());
                        }
                    }
                }
            } else {
                resto.push(a.clone());
            }
            i += 1;
        }
        Ok(Args { comando, resto, opcoes, ultimo_diag: std::cell::RefCell::new(None) })
    }

    pub fn opcao(&self, nome: &str) -> Option<String> {
        self.opcoes.get(nome).cloned()
    }

    /// Valor de uma opção, caindo para a variável de ambiente e, por último,
    /// para um prompt que não ecoa.
    pub fn segredo(&self, nome: &str, env: &str, rotulo: &str) -> Result<String, String> {
        if let Some(v) = self.opcao(nome) {
            return Ok(v);
        }
        if let Ok(v) = std::env::var(env) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
        perguntar(rotulo, true)
    }

    pub fn texto(&self, nome: &str, env: &str, rotulo: &str) -> Result<String, String> {
        if let Some(v) = self.opcao(nome) {
            return Ok(v);
        }
        if let Ok(v) = std::env::var(env) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
        perguntar(rotulo, false)
    }
}

/// Pergunta no terminal. Com `oculto`, desliga o eco via `stty`.
///
/// `stty` em vez de termios direto para não trazer uma dependência de libc só
/// por isto; se ele não existir, o valor é lido com eco e o usuário é avisado,
/// que é melhor que recusar a operação.
fn perguntar(rotulo: &str, oculto: bool) -> Result<String, String> {
    let entrada = std::io::stdin();
    if !entrada.is_terminal() {
        return Err(format!(
            "{rotulo} não foi informado e a entrada não é um terminal: \
             use a opção ou a variável de ambiente"
        ));
    }
    let escondeu = oculto && stty(&["-echo"]);
    if oculto && !escondeu {
        eprintln!("(aviso: não consegui desligar o eco; o valor vai aparecer na tela)");
    }
    eprint!("{rotulo}: ");
    let _ = std::io::stderr().flush();

    let mut linha = String::new();
    let leitura = entrada.read_line(&mut linha);
    if escondeu {
        stty(&["echo"]);
        eprintln!();
    }
    leitura.map_err(|e| format!("não li {rotulo}: {e}"))?;
    let valor = linha.trim().to_string();
    if valor.is_empty() {
        return Err(format!("{rotulo} vazio"));
    }
    Ok(valor)
}

fn stty(args: &[&str]) -> bool {
    Command::new("stty")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// --- comandos --------------------------------------------------------------

type Saida = Result<(), remoteid_tipos::Error>;

fn abrir_motor(args: &Args) -> Result<Motor, remoteid_tipos::Error> {
    let mut opcoes = Opcoes::default();
    if let Some(d) = args.opcao("dir") {
        opcoes.dir_dados = PathBuf::from(d);
    }
    if let Some(t) = args.opcao("timeout") {
        if let Ok(s) = t.parse::<u64>() {
            opcoes.timeout = std::time::Duration::from_secs(s);
        }
    }
    // Trocar a base serve para homologação e para apontar a um servidor de
    // teste; é o que os testes de integração usam.
    if let Some(u) = args.opcao("remoteid-url") {
        opcoes.remoteid_url = u;
    }
    if let Some(u) = args.opcao("certinext-url") {
        opcoes.certinext_url = u;
    }
    let motor = Motor::abrir(opcoes)?;
    *args.ultimo_diag.borrow_mut() = motor.caminho_diag();
    Ok(motor)
}

fn rodar(args: &Args) -> Saida {
    use remoteid_tipos::Error;
    match args.comando.as_str() {
        "estado" => cmd_estado(args),
        "conectividade" => cmd_conectividade(args),
        "login" => cmd_login(args),
        "registrar" => cmd_registrar(args),
        "carteira" => cmd_carteira(args),
        "celular" => cmd_celular(args),
        "preparar" => cmd_preparar(args),
        "harness" => cmd_harness(args),
        "assinar" => cmd_assinar(args),
        "modo" => cmd_modo(args),
        "chave-publica" => cmd_chave_publica(args),
        "diagnostico" => cmd_diagnostico(args),
        outro => Err(Error::uso(format!(
            "comando desconhecido: {outro} (use --help)"
        ))),
    }
}

fn cmd_estado(args: &Args) -> Saida {
    let motor = abrir_motor(args)?;
    let e = &motor.estado;
    println!("titular       : {}", e.nome.as_deref().unwrap_or("(sem login ainda)"));
    println!("cpf           : {}", e.cpf.as_deref().unwrap_or("-"));
    println!("userId        : {}", opt(e.user_id));
    println!("organizacaoId : {}", opt(e.organizacao_id));
    println!("codigoDesktop : {}", e.codigo_desktop.as_deref().unwrap_or("(não registrado)"));
    println!("modo          : {} (política LOCAL, não vem do servidor)", e.auth_mode);
    match e.usuario_possui_codigo_push {
        Some(true) => println!("celular       : pareado (push é possível)"),
        Some(false) => println!("celular       : não pareado"),
        None => println!("celular       : não consultado"),
    }
    if e.certificados.is_empty() {
        println!("certificado   : (carteira não baixada)");
    } else {
        for c in &e.certificados {
            println!("certificado   : serial {} / {}", c.serial_number, c.issue);
        }
    }
    if let Some(p) = motor.caminho_diag() {
        println!("log desta run : {}", p.display());
    }
    Ok(())
}

fn cmd_conectividade(args: &Args) -> Saida {
    let motor = abrir_motor(args)?;
    let data = motor.hierarquias()?;
    let n = data.get("hierarchies").and_then(|h| h.as_array()).map_or(0, |a| a.len());
    println!("servidor respondeu: {n} hierarquias");
    Ok(())
}

fn cmd_login(args: &Args) -> Saida {
    let mut motor = abrir_motor(args)?;
    fazer_login(&mut motor, args)?;
    motor.salvar_estado()?;
    println!("login ok: {}", motor.estado.nome.as_deref().unwrap_or("-"));
    Ok(())
}

fn fazer_login(motor: &mut Motor, args: &Args) -> Saida {
    use remoteid_tipos::Error;
    let email = args
        .texto("email", "REMOTEID_EMAIL", "e-mail do RemoteID")
        .map_err(Error::uso)?;
    let senha = args
        .segredo("senha", "REMOTEID_SENHA", "senha do RemoteID")
        .map_err(Error::uso)?;
    motor.login(&email, &senha)
}

fn cmd_registrar(args: &Args) -> Saida {
    let mut motor = abrir_motor(args)?;
    // O registro precisa do JWT, que não persiste: faz o login na mesma run.
    fazer_login(&mut motor, args)?;
    let nome = args.opcao("nome").unwrap_or_else(nome_padrao);
    let codigo = motor.registrar(&nome)?;
    motor.salvar_estado()?;
    println!("registrado: codigoDesktop {codigo}");
    Ok(())
}

fn cmd_carteira(args: &Args) -> Saida {
    let mut motor = abrir_motor(args)?;
    let certs = motor.carteira()?.to_vec();
    motor.salvar_estado()?;
    for c in &certs {
        println!("serial {}\nemissor {}", c.serial_number, c.issue);
    }
    Ok(())
}

fn cmd_celular(args: &Args) -> Saida {
    let mut motor = abrir_motor(args)?;
    let tem = motor.status_celular()?;
    motor.salvar_estado()?;
    println!(
        "celular pareado: {}",
        if tem { "sim" } else { "não" }
    );
    println!(
        "(informativo: o app oficial lê este valor e mesmo assim grava o modo \
         como `local`, ou seja, pin+otp)"
    );
    Ok(())
}

fn cmd_preparar(args: &Args) -> Saida {
    let mut motor = abrir_motor(args)?;
    fazer_login(&mut motor, args)?;
    println!("login ok: {}", motor.estado.nome.as_deref().unwrap_or("-"));

    let nome = args.opcao("nome").unwrap_or_else(nome_padrao);
    let codigo = motor.registrar(&nome)?;
    motor.salvar_estado()?;
    println!("registrado: codigoDesktop {codigo}");

    // Não é pré-requisito da assinatura; roda para deixar o estado completo.
    match motor.status_celular() {
        Ok(tem) => println!("celular pareado: {}", if tem { "sim" } else { "não" }),
        Err(e) => println!("celular: não consultado ({e})"),
    }

    let certs = motor.carteira()?.to_vec();
    motor.salvar_estado()?;
    for c in &certs {
        println!("certificado: serial {} / {}", c.serial_number, c.issue);
    }
    println!("\npronto. agora: remoteid assinar --arquivo <arquivo>");
    Ok(())
}

fn cmd_harness(args: &Args) -> Saida {
    let mut h = harness::Harness::novo(abrir_motor(args)?);
    h.rodar(args);
    let caminho = h.salvar()?;
    println!("\nrelatório: {}", caminho.display());
    println!(
        "Envie esse arquivo por canal privado. Senha, PIN e OTP não estão nele,\n\
         mas ele identifica o titular do certificado."
    );
    Ok(())
}

fn cmd_assinar(args: &Args) -> Saida {
    use remoteid_tipos::Error;
    let motor = abrir_motor(args)?;
    let digest = digest_da_entrada(args)?;
    let modo = motor.estado.modo();

    let fatores = match modo.estado() {
        remoteid_autorizacao::Estado::PromptForPush => {
            eprintln!(
                "modo `push`: o servidor vai esperar a aprovação no celular. \
                 Este caminho nunca foi testado com uma conta real."
            );
            Fatores::Push
        }
        remoteid_autorizacao::Estado::MobileId => {
            return Err(Error::uso(
                "modo `mobileId` é outra estratégia de assinatura, fora do RemoteID; \
                 use `remoteid modo local`",
            ))
        }
        remoteid_autorizacao::Estado::Interativo => {
            let pin = args
                .segredo("pin", "REMOTEID_PIN", "PIN do certificado")
                .map_err(Error::uso)?;
            // O OTP é pedido DEPOIS do PIN e imediatamente antes da chamada:
            // ele vale uns 30 segundos e é de uso único.
            let otp = args
                .segredo("otp", "REMOTEID_OTP", "código do autenticador (OTP)")
                .map_err(Error::uso)?;
            Fatores::PinOtp { pin, otp }
        }
    };

    // Com --pkcs7 o que vai para o HSM NÃO é o digest do documento: é o digest
    // dos atributos assinados, que contêm o do documento (RFC 5652 §5.4). Por
    // isso o montador entra ANTES da chamada de assinatura, e não depois.
    if let Some(saida) = args.opcao("pkcs7") {
        // A combinação de opções é checada antes de tocar no estado: reclamar
        // de "--anexar sem --arquivo" só depois de falhar por falta de carteira
        // manda o usuário consertar a coisa errada.
        let anexar = if args.opcao("anexar").is_some() {
            Some(conteudo_da_entrada(args)?)
        } else {
            None
        };

        let cert = motor.estado.certificado()?;
        let cert_der = de_b64(cert.base64.as_deref().ok_or_else(|| {
            Error::estado(
                "o certificado guardado não tem o DER; rode `carteira` de novo",
            )
        })?)?;
        let montador = Montador::novo(&cert_der, &digest, agora(), anexar)?;
        let assinatura = motor.assinar_digest(montador.digest_a_assinar(), &fatores)?;
        let p7s = montador.finalizar(&assinatura)?;

        std::fs::write(&saida, &p7s)?;
        eprintln!("PKCS#7 ({} bytes) em {saida}", p7s.len());
        eprintln!(
            "conferir: openssl cms -verify -inform DER -in {saida} -content <documento>"
        );
        return Ok(());
    }

    let assinatura = motor.assinar_digest(&digest, &fatores)?;

    match args.opcao("saida") {
        Some(caminho) => {
            std::fs::write(&caminho, &assinatura)?;
            eprintln!("assinatura crua ({} bytes) em {caminho}", assinatura.len());
        }
        None => println!("{}", b64(&assinatura)),
    }
    Ok(())
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// O conteúdo em si, para a assinatura anexada. Só faz sentido com --arquivo:
/// anexar exige ter os bytes, e um digest solto não os tem.
fn conteudo_da_entrada(args: &Args) -> Result<Vec<u8>, remoteid_tipos::Error> {
    match args.opcao("arquivo") {
        Some(caminho) => Ok(std::fs::read(&caminho)?),
        None => Err(remoteid_tipos::Error::uso(
            "--anexar precisa de --arquivo: para embutir o conteúdo é preciso \
             tê-lo, e um --hash é só o resumo",
        )),
    }
}

/// O digest a assinar, das quatro formas de entrada.
fn digest_da_entrada(args: &Args) -> Result<Vec<u8>, remoteid_tipos::Error> {
    use remoteid_tipos::Error;
    if let Some(caminho) = args.opcao("arquivo") {
        let dados = std::fs::read(&caminho)?;
        return Ok(sha256(&dados).to_vec());
    }
    if let Some(h) = args.opcao("hash") {
        let d = de_b64(&h)?;
        return conferir_digest(d);
    }
    if let Some(h) = args.opcao("hash-hex") {
        let limpo: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        if limpo.len() % 2 != 0 {
            return Err(Error::uso("hash-hex com número ímpar de dígitos"));
        }
        let d: Result<Vec<u8>, _> = (0..limpo.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&limpo[i..i + 2], 16))
            .collect();
        return conferir_digest(d.map_err(|e| Error::uso(format!("hash-hex inválido: {e}")))?);
    }
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Err(Error::uso(
            "nada para assinar: use --arquivo, --hash, --hash-hex ou mande o conteúdo pela entrada padrão",
        ));
    }
    Ok(sha256(&buf).to_vec())
}

fn conferir_digest(d: Vec<u8>) -> Result<Vec<u8>, remoteid_tipos::Error> {
    use remoteid_tipos::Error;
    if d.len() != 32 {
        return Err(Error::uso(format!(
            "o digest tem de ser SHA-256 (32 bytes); veio com {}. \
             Se você passou o ARQUIVO em vez do hash, use --arquivo.",
            d.len()
        )));
    }
    Ok(d)
}

fn cmd_modo(args: &Args) -> Saida {
    use remoteid_tipos::Error;
    let alvo = args
        .resto
        .first()
        .ok_or_else(|| Error::uso("informe o modo: local, push, mobileId"))?;
    let modo: Modo = alvo.parse().unwrap_or_default();
    let mut motor = abrir_motor(args)?;
    motor.definir_modo(&modo);
    motor.salvar_estado()?;
    println!("modo agora: {modo} (estado interno {:?})", modo.estado());
    if matches!(modo, Modo::Outro(_)) {
        println!(
            "aviso: o app oficial só reconhece `push`, `local` e `mobileId`. \
             Qualquer outro valor, `otp` e `pin` inclusive, cai no mesmo caminho \
             do `local`: pin + otp juntos."
        );
    }
    Ok(())
}

fn cmd_chave_publica(args: &Args) -> Saida {
    let motor = abrir_motor(args)?;
    print!("{}", motor.chave_publica_pem()?);
    Ok(())
}

fn cmd_diagnostico(args: &Args) -> Saida {
    let motor = abrir_motor(args)?;
    let dir = remoteid_caminhos::dir_diag();
    println!("diretório: {}", dir.display());
    if let Some(p) = motor.caminho_diag() {
        println!("desta execução: {}", p.display());
    }
    let mut arquivos: Vec<_> = std::fs::read_dir(&dir)
        .map(|it| it.flatten().map(|e| e.path()).collect())
        .unwrap_or_else(|_| Vec::new());
    arquivos.sort();
    println!("\nexecuções guardadas ({}):", arquivos.len());
    for a in arquivos.iter().rev().take(10) {
        let bytes = a.metadata().map(|m| m.len()).unwrap_or(0);
        println!("  {} ({bytes} bytes)", a.display());
    }
    println!(
        "\nOs segredos (senha, pin, otp) nunca são gravados; tokens aparecem só \
         como impressão digital.\nPara anexar a um relatório de bug, mande o \
         arquivo da execução que falhou."
    );
    Ok(())
}

pub fn nome_padrao() -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if host.is_empty() {
        "remoteid-linux".into()
    } else {
        format!("remoteid-linux@{host}")
    }
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}
