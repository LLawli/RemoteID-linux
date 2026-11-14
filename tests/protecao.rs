//! A memória do `remoteid servir` fechada para outro processo do mesmo
//! usuário, e sem core dump numa queda.

use std::fs::{self, File};
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Quem o servir vira quando o teste roda como root, como na CI.
const NOBODY: u32 = 65534;

#[test]
fn o_servir_nao_deixa_ler_a_memoria_nem_gera_core_dump() {
    let raiz = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("protecao");
    let _ = fs::remove_dir_all(&raiz);
    fs::create_dir_all(&raiz).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_remoteid"));
    cmd.arg("servir")
        .env("REMOTEID_HOME", &raiz)
        .env("REMOTEID_COFRE", "nenhum")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Um processo do root já tem o `/proc/<pid>` do root: o dono só prova o
    // `dumpable` 0 se o servir for de outro usuário.
    // SAFETY: geteuid não tem pré-condição.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        std::os::unix::fs::chown(&raiz, Some(NOBODY), Some(NOBODY)).unwrap();
        cmd.uid(NOBODY).gid(NOBODY);
    }
    let mut filho = cmd.spawn().unwrap();
    let proc = format!("/proc/{}", filho.id());

    // O `dumpable` muda logo depois do execve: espera os arquivos passarem
    // ao root, com um teto para o teste não travar se nunca passarem.
    let mem = format!("{proc}/mem");
    let prazo = Instant::now() + Duration::from_secs(5);
    while fs::metadata(&mem).unwrap().uid() != 0 && Instant::now() < prazo {
        std::thread::sleep(Duration::from_millis(20));
    }
    let dono = fs::metadata(&mem).unwrap().uid();
    let abrir = File::open(&mem).map(|_| ()).map_err(|e| e.kind());
    let limites = fs::read_to_string(format!("{proc}/limits")).unwrap();

    let _ = filho.kill();
    let _ = filho.wait();

    assert_eq!(dono, 0, "{mem} não passou ao root");
    // O root abre o `mem` de qualquer processo, protegido ou não.
    if !root {
        assert_eq!(abrir, Err(ErrorKind::PermissionDenied));
    }
    let core = limites
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    let campos: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(&campos[4..6], ["0", "0"], "{core}");
}
