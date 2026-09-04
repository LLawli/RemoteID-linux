//! Utilitários do socket UNIX: o caminho e o bind.
//!
//! Depois da unificação de 03/09/2026 ([[remoteid-app-unificado]]), quem
//! ATENDE o socket é o app (`remoteid-gtk::servidor`), integrado ao loop do
//! GTK — não há mais um `servir()` bloqueante aqui, nem adoção de socket do
//! systemd (o socket-activation foi abandonado por não cruzar limpo a
//! fronteira do sandbox Flatpak). Restam só as duas peças que o app reusa: o
//! caminho do socket e o bind manual com permissão 0600.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// Caminho default do socket.
///
/// `REMOTEID_SOCKET` sobrescreve, com o caminho inteiro. É o que permite o
/// empacotamento Flatpak apontar app E módulo para o mesmo caminho
/// bind-montado compartilhado entre o sandbox e o host (o `$XDG_RUNTIME_DIR`
/// visto de dentro do sandbox não é o mesmo do host). Ver
/// [[remoteid-flatpak-daemon]].
///
/// Sem a env, `$XDG_RUNTIME_DIR/remoteid.sock`. O `XDG_RUNTIME_DIR` é criado
/// pelo login manager por sessão de usuário, vive em tmpfs, e some no logout —
/// o socket some junto.
pub fn caminho_padrao() -> PathBuf {
    if let Some(s) = std::env::var("REMOTEID_SOCKET").ok().filter(|v| !v.is_empty()) {
        return PathBuf::from(s);
    }
    // Modo de teste: o socket mora no dir de teste, junto do estado, para o app
    // e o módulo se acharem com um único interruptor (`TEST_URL`).
    if remoteid_caminhos::em_teste() {
        return PathBuf::from(remoteid_caminhos::DIR_TESTE).join("remoteid.sock");
    }
    let base = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", nix_uid()));
    PathBuf::from(base).join("remoteid.sock")
}

fn nix_uid() -> u32 {
    // Sem depender de libc: /proc/self/status tem `Uid:  <real> <eff> ...`.
    if let Ok(txt) = std::fs::read_to_string("/proc/self/status") {
        for linha in txt.lines() {
            if let Some(v) = linha.strip_prefix("Uid:") {
                if let Some(uid_str) = v.split_whitespace().next() {
                    if let Ok(n) = uid_str.parse::<u32>() {
                        return n;
                    }
                }
            }
        }
    }
    1000
}

/// Bind manual em `caminho`, com permissão 0600. Se já existe socket no
/// caminho, RECUSA subir — apagar às cegas mataria um app vivo. O chamador
/// (`servidor::iniciar`) remove um socket órfão de antes ANTES de chamar isto.
pub fn bind_manual(caminho: &Path) -> std::io::Result<UnixListener> {
    if let Some(pai) = caminho.parent() {
        std::fs::create_dir_all(pai)?;
    }
    if caminho.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} já existe: pode haver outra instância ativa. Apague à mão se tem certeza.",
                caminho.display()
            ),
        ));
    }
    let listener = UnixListener::bind(caminho)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(caminho, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `caminho_padrao` lê variáveis de ambiente, que são globais do processo.
    // Como o cargo roda os testes em paralelo na mesma binária, os dois testes
    // que mexem em env precisam serializar entre si, ou um vê a env do outro
    // (ex.: `REMOTEID_SOCKET` setado por um faz o teste do XDG falhar).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn caminho_padrao_e_no_xdg_runtime_dir_quando_setado() {
        let _guarda = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Guarda e restaura para não vazar entre testes.
        let salvo_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        let salvo_sock = std::env::var("REMOTEID_SOCKET").ok();
        std::env::remove_var("REMOTEID_SOCKET"); // o override venceria o XDG
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/test-runtime-xyz");
        assert_eq!(caminho_padrao(), PathBuf::from("/tmp/test-runtime-xyz/remoteid.sock"));
        match salvo_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        if let Some(v) = salvo_sock {
            std::env::set_var("REMOTEID_SOCKET", v);
        }
    }

    #[test]
    fn remoteid_socket_sobrescreve_o_caminho() {
        let _guarda = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Guarda e restaura para não vazar entre testes.
        let salvo = std::env::var("REMOTEID_SOCKET").ok();
        std::env::set_var("REMOTEID_SOCKET", "/run/flatpak/remoteid-compartilhado.sock");
        assert_eq!(
            caminho_padrao(),
            PathBuf::from("/run/flatpak/remoteid-compartilhado.sock")
        );
        match salvo {
            Some(v) => std::env::set_var("REMOTEID_SOCKET", v),
            None => std::env::remove_var("REMOTEID_SOCKET"),
        }
    }

    #[test]
    fn bind_manual_recusa_arquivo_existente() {
        let p = std::env::temp_dir().join(format!("dtid-sock-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"").unwrap();
        let e = bind_manual(&p).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        std::fs::remove_file(&p).unwrap();
    }
}
