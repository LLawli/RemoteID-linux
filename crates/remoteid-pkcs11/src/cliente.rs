//! O braço de PRODUÇÃO do `C_Sign`: cliente do socket do app.
//!
//! Quando NÃO há chave local de teste, a assinatura vem do app
//! (`remoteid-app`): o módulo manda o digest SHA-256 e recebe os 256 bytes
//! crus. É o app que cuida do PIN/OTP (diálogo), do `tokensessao`, do
//! `requestHash` e do cache — aqui só falamos o protocolo.
//!
//! O socket é `$REMOTEID_SOCKET` (o app em modo de teste aponta para /tmp) ou
//! `$XDG_RUNTIME_DIR/remoteid.sock`. Não escrevemos em stdout/stderr (o
//! hospedeiro é dono deles) e não estouramos panic pela fronteira C (o
//! chamador está dentro de um `entrada!`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use cryptoki_sys::*;

use remoteid_cripto::{b64, de_b64};
use remoteid_protocolo::{CodigoErro, Requisicao, Resposta, SucessoResposta};

/// Pede ao app a assinatura RSA do `digest` (SHA-256, 32 bytes). Devolve os
/// 256 bytes crus, ou um `CK_RV` traduzido do erro do app.
pub fn assinar_pelo_app(digest: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let caminho = caminho_socket();
    let stream = UnixStream::connect(&caminho).map_err(|_| CKR_DEVICE_ERROR)?;
    // A assinatura pode demorar: o app faz rede E mostra o diálogo de PIN/OTP,
    // que o usuário leva segundos para preencher. Um teto generoso evita
    // travar para sempre se o app morrer no meio.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));

    let req = Requisicao::Sign {
        digest_b64: b64(digest),
        hospedeiro: comm_do_processo(),
    };
    let mut linha = serde_json::to_string(&req).map_err(|_| CKR_FUNCTION_FAILED)?;
    linha.push('\n');

    let mut escritor = stream.try_clone().map_err(|_| CKR_DEVICE_ERROR)?;
    escritor
        .write_all(linha.as_bytes())
        .map_err(|_| CKR_DEVICE_ERROR)?;
    escritor.flush().map_err(|_| CKR_DEVICE_ERROR)?;

    let mut leitor = BufReader::new(stream);
    let mut resp = String::new();
    leitor.read_line(&mut resp).map_err(|_| CKR_DEVICE_ERROR)?;
    if resp.trim().is_empty() {
        return Err(CKR_DEVICE_ERROR);
    }

    let resposta: Resposta =
        serde_json::from_str(resp.trim_end()).map_err(|_| CKR_FUNCTION_FAILED)?;
    match resposta {
        Resposta::Sucesso(SucessoResposta::Sign { assinatura_b64, .. }) => {
            de_b64(&assinatura_b64).map_err(|_| CKR_FUNCTION_FAILED)
        }
        Resposta::Sucesso(_) => Err(CKR_FUNCTION_FAILED),
        Resposta::Falha { codigo, .. } => Err(traduzir_erro(codigo)),
    }
}

/// Traduz o erro do app para um código Cryptoki que o hospedeiro entenda.
fn traduzir_erro(codigo: CodigoErro) -> CK_RV {
    match codigo {
        // O usuário fechou o diálogo de PIN/OTP: o poppler mostra "cancelado".
        CodigoErro::Cancelado => CKR_FUNCTION_CANCELED,
        _ => CKR_FUNCTION_FAILED,
    }
}

/// `$REMOTEID_SOCKET`, senão `$XDG_RUNTIME_DIR/remoteid.sock`. Igual à regra
/// do app (`socket::caminho_padrao`), mantida à mão porque um cdylib não deve
/// arrastar o crate do app só por uma linha.
fn caminho_socket() -> PathBuf {
    if let Some(s) = std::env::var("REMOTEID_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
    {
        return PathBuf::from(s);
    }
    // Modo de teste: mesmo socket que o app em teste bina (via `TEST_URL`), sem
    // precisar de `REMOTEID_SOCKET` no Papers.
    if remoteid_caminhos::em_teste() {
        return PathBuf::from(remoteid_caminhos::DIR_TESTE).join("remoteid.sock");
    }
    let base = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", uid()));
    PathBuf::from(base).join("remoteid.sock")
}

/// O `comm` do processo hospedeiro (Papers, Firefox…), para o app mostrar
/// "Solicitado por <host>" no diálogo. `None` se não der para ler.
fn comm_do_processo() -> Option<String> {
    std::fs::read_to_string("/proc/self/comm")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn uid() -> u32 {
    if let Ok(txt) = std::fs::read_to_string("/proc/self/status") {
        for linha in txt.lines() {
            if let Some(v) = linha.strip_prefix("Uid:") {
                if let Some(n) = v.split_whitespace().next().and_then(|s| s.parse().ok()) {
                    return n;
                }
            }
        }
    }
    1000
}
