//! Sem chaveiro no sistema, a senha da conta fica num arquivo cifrado com um
//! PIN numérico que a pessoa cria ao entrar (de [`MIN_DIGITOS`] a
//! [`MAX_DIGITOS`] dígitos). O PIN é pedido na primeira assinatura de cada
//! processo, e a senha aberta fica na memória dele até ele fechar.
//!
//! [`MAX_ERROS`] PINs errados seguidos apagam o arquivo, e o motor sai da
//! conta: para voltar, só entrando de novo. O contador mora no próprio
//! arquivo, então vale entre processos.
//!
//! É um recurso relativamente seguro, e não mais que isso: o limite de erros
//! só vale aqui dentro. Quem copiar o arquivo pode testar os PINs fora, e o
//! que o atrasa é o Argon2id (cada tentativa custa [`MEMORIA_KIB`] de memória
//! e algumas centenas de milissegundos).

use std::io;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cripto::{b64, de_b64};
use crate::estado::gravar_privado;

pub const MIN_DIGITOS: usize = 4;
pub const MAX_DIGITOS: usize = 6;
/// Quantos PINs errados seguidos apagam o arquivo e saem da conta.
pub const MAX_ERROS: u32 = 5;

/// O custo do Argon2id: 64 MiB e três passadas por tentativa.
const MEMORIA_KIB: u32 = 64 * 1024;
const PASSADAS: u32 = 3;
const VERSAO: u32 = 1;

/// Se `pin` serve: só dígitos, de 4 a 6.
pub fn valido(pin: &str) -> bool {
    (MIN_DIGITOS..=MAX_DIGITOS).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Serialize, Deserialize)]
struct Arquivo {
    versao: u32,
    sal: String,
    nonce: String,
    cifrado: String,
    /// PINs errados seguidos.
    erros: u32,
}

/// O que deu abrir o arquivo com um PIN.
pub enum Abertura {
    Senha(Zeroizing<String>),
    /// PIN errado; faltam `restantes` erros para o arquivo sumir.
    Errado {
        restantes: u32,
    },
    /// O último erro permitido: o arquivo já foi apagado.
    Bloqueado,
}

fn chave(pin: &str, sal: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(MEMORIA_KIB, PASSADAS, 1, Some(32))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut chave = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), sal, chave.as_mut())
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(chave)
}

fn invalido(motivo: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, motivo)
}

/// Cifra `senha` com `pin`, amarrada ao `email` da conta, e zera o contador.
pub fn cifrar(caminho: &Path, email: &str, senha: &str, pin: &str) -> io::Result<()> {
    if !valido(pin) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "o PIN tem de ter de 4 a 6 dígitos",
        ));
    }
    let mut sal = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut sal);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cifra = ChaCha20Poly1305::new(chave(pin, &sal)?.as_ref().into());
    let cifrado = cifra
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: senha.as_bytes(),
                aad: email.as_bytes(),
            },
        )
        .map_err(|_| io::Error::other("a cifra falhou"))?;
    gravar(
        caminho,
        &Arquivo {
            versao: VERSAO,
            sal: b64(&sal),
            nonce: b64(&nonce),
            cifrado: b64(&cifrado),
            erros: 0,
        },
    )
}

fn gravar(caminho: &Path, arquivo: &Arquivo) -> io::Result<()> {
    gravar_privado(
        caminho,
        &serde_json::to_vec(arquivo).expect("o arquivo sempre vira JSON"),
    )
}

/// Abre o arquivo com `pin`. Um erro soma no contador; o último apaga o
/// arquivo.
pub fn abrir(caminho: &Path, email: &str, pin: &str) -> io::Result<Abertura> {
    let mut arquivo: Arquivo =
        serde_json::from_slice(&std::fs::read(caminho)?).map_err(|e| invalido(&e.to_string()))?;
    if arquivo.versao != VERSAO {
        return Err(invalido("versão desconhecida do arquivo da senha"));
    }
    let campo = |nome: &str, valor: &str| de_b64(valor).ok_or_else(|| invalido(nome));
    let sal = campo("sal", &arquivo.sal)?;
    let nonce = campo("nonce", &arquivo.nonce)?;
    let cifrado = campo("cifrado", &arquivo.cifrado)?;
    if nonce.len() != 12 {
        return Err(invalido("nonce"));
    }
    let aberto = if valido(pin) {
        ChaCha20Poly1305::new(chave(pin, &sal)?.as_ref().into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &cifrado,
                    aad: email.as_bytes(),
                },
            )
            .ok()
    } else {
        None
    };
    match aberto.map(String::from_utf8) {
        Some(Ok(senha)) => {
            if arquivo.erros > 0 {
                arquivo.erros = 0;
                gravar(caminho, &arquivo)?;
            }
            Ok(Abertura::Senha(Zeroizing::new(senha)))
        }
        _ => {
            arquivo.erros += 1;
            if arquivo.erros >= MAX_ERROS {
                apagar(caminho)?;
                return Ok(Abertura::Bloqueado);
            }
            gravar(caminho, &arquivo)?;
            Ok(Abertura::Errado {
                restantes: MAX_ERROS - arquivo.erros,
            })
        }
    }
}

pub fn apagar(caminho: &Path) -> io::Result<()> {
    match std::fs::remove_file(caminho) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caminho(nome: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("remoteid-pin-{}-{nome}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("senha.cifrada")
    }

    fn senha(a: Abertura) -> Option<String> {
        match a {
            Abertura::Senha(s) => Some(s.to_string()),
            _ => None,
        }
    }

    #[test]
    fn so_digitos_de_quatro_a_seis() {
        for bom in ["1234", "12345", "123456"] {
            assert!(valido(bom), "{bom}");
        }
        for ruim in ["123", "1234567", "12a4", "", "١٢٣٤"] {
            assert!(!valido(ruim), "{ruim}");
        }
    }

    #[test]
    fn o_pin_certo_abre_e_a_senha_nao_fica_em_claro() {
        let c = caminho("certo");
        cifrar(&c, "a@b", "senha-da-conta", "4321").unwrap();
        let bruto = std::fs::read_to_string(&c).unwrap();
        assert!(!bruto.contains("senha-da-conta"));
        assert_eq!(
            senha(abrir(&c, "a@b", "4321").unwrap()).as_deref(),
            Some("senha-da-conta")
        );
        // Amarrada à conta: o mesmo arquivo não abre para outro e-mail.
        assert!(matches!(
            abrir(&c, "outra@b", "4321").unwrap(),
            Abertura::Errado { .. }
        ));
    }

    #[test]
    fn os_erros_contam_entre_aberturas_zeram_no_acerto_e_o_ultimo_apaga() {
        let c = caminho("erros");
        cifrar(&c, "a@b", "s", "4321").unwrap();
        assert!(matches!(
            abrir(&c, "a@b", "0000").unwrap(),
            Abertura::Errado { restantes: 4 }
        ));
        assert!(senha(abrir(&c, "a@b", "4321").unwrap()).is_some());
        for restantes in (1..MAX_ERROS).rev() {
            assert!(matches!(
                abrir(&c, "a@b", "0000").unwrap(),
                Abertura::Errado { restantes: r } if r == restantes
            ));
        }
        assert!(matches!(
            abrir(&c, "a@b", "0000").unwrap(),
            Abertura::Bloqueado
        ));
        assert!(!c.exists());
    }
}
