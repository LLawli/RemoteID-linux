//! Adaptador de ambiente: os fatos de host reais. Implementa [`remoteid_portas::Ambiente`].
//!
//! São os dois fatos que o protocolo precisa e que não são armazenamento: o
//! hostname (`dominioRede`, que o servidor recusa vazio) e o usuário local
//! (`nomeUsuarioLocal`). Nos testes um ambiente falso substitui este.

use remoteid_portas::Ambiente;

pub struct AmbienteSistema;

impl Ambiente for AmbienteSistema {
    fn usuario_local(&self) -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "linux".into())
    }

    /// Hostname para `dominioRede`, que NÃO pode ir vazio.
    fn hostname(&self) -> String {
        // Sem dependência de libc: no Linux o kernel expõe o hostname em sysfs.
        let candidatos = ["/proc/sys/kernel/hostname", "/etc/hostname"];
        for c in candidatos {
            if let Ok(txt) = std::fs::read_to_string(c) {
                let nome = txt.trim();
                if !nome.is_empty() {
                    return nome.to_string();
                }
            }
        }
        std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "linux".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_e_usuario_nunca_voltam_vazios() {
        // O servidor recusa dominioRede vazio (DomainNameLeftBlank).
        assert!(!AmbienteSistema.hostname().is_empty());
        assert!(!AmbienteSistema.usuario_local().is_empty());
    }
}
