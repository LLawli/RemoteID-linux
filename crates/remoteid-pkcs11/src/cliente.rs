//! O braço de PRODUÇÃO do `C_Sign`: cliente do socket do app.
//!
//! Quando NÃO há chave local de teste, a assinatura vem do app
//! (`remoteid-app`): o módulo manda o que assinar (o hash SHA-256, ou o bloco
//! pronto no modo cru) e recebe os 256 bytes crus. É o app que cuida do
//! PIN/OTP (diálogo), do `tokensessao`, do `requestHash` e do cache — aqui só
//! falamos o protocolo.
//!
//! O socket é `$REMOTEID_SOCKET` (o app em modo de teste aponta para /tmp) ou
//! `$XDG_RUNTIME_DIR/remoteid.sock`. Não escrevemos em stdout/stderr (o
//! hospedeiro é dono deles) e não estouramos panic pela fronteira C (o
//! chamador está dentro de um `entrada!`).
//!
//! Quando o app não responde (não está aberto, ou morreu no meio), o módulo
//! deixa uma linha em `modulo-pkcs11.jsonl`, no diretório do diag. Sem isso a
//! falha não aparecia em lugar nenhum: o app é quem grava o diag, e um pedido
//! que nunca chega a ele não deixa rastro. Foi o que fez a issue 26 parecer um
//! problema de protocolo quando era só o app fechado.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cryptoki_sys::*;
use serde_json::json;

use remoteid_cripto::{b64, de_b64};
use remoteid_diag_jsonl::Diag;
use remoteid_protocolo::{CodigoErro, Requisicao, Resposta, SucessoResposta};
use remoteid_protocolo_servidor::algoritmo::Algoritmo;

/// Pede ao app a assinatura RSA de `dados`, que são o hash SHA-256 de 32 bytes
/// (`Algoritmo::Sha256`) ou o bloco pronto de até 245 bytes
/// (`Algoritmo::Cru`, em que o HSM só aplica o padding). Devolve os 256 bytes
/// crus, ou um `CK_RV` traduzido do erro do app.
pub fn assinar_pelo_app(algoritmo: Algoritmo, dados: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let diag = remoteid_caminhos::caminho_diag_modulo(&remoteid_caminhos::dir_diag());
    assinar_por(&caminho_socket(), &diag, algoritmo, dados)
}

/// [`assinar_pelo_app`] com o socket e o arquivo de diag explícitos, para os
/// testes não dependerem do ambiente nem escreverem no diag de verdade.
fn assinar_por(
    socket: &Path,
    diag: &Path,
    algoritmo: Algoritmo,
    dados: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    // O literal vai sempre, mesmo sendo o padrão: o socket carrega a string
    // opaca e o daemon converte; a fonte dos valores é o `Algoritmo`.
    let hospedeiro = comm_do_processo();
    let req = Requisicao::Sign {
        algoritmo: Some(algoritmo.nome().to_string()),
        digest_b64: b64(dados),
        hospedeiro: hospedeiro.clone(),
    };
    let mut linha = serde_json::to_string(&req).map_err(|_| CKR_FUNCTION_FAILED)?;
    linha.push('\n');

    let resp = match conversar(socket, &linha) {
        Ok(resp) => resp,
        Err(falha) => {
            registrar_falha(diag, socket, hospedeiro.as_deref(), algoritmo, &falha);
            return Err(CKR_DEVICE_ERROR);
        }
    };

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

/// Onde a conversa com o app parou, para o diag dizer se ele nem estava no ar
/// ou se sumiu no meio.
struct FalhaDeConversa {
    etapa: &'static str,
    erro: Option<std::io::Error>,
}

impl FalhaDeConversa {
    fn em(etapa: &'static str) -> impl FnOnce(std::io::Error) -> FalhaDeConversa {
        move |erro| FalhaDeConversa {
            etapa,
            erro: Some(erro),
        }
    }
}

/// Manda uma linha e lê uma linha. Toda falha aqui é do app (ausente, morto
/// ou calado), e vira `CKR_DEVICE_ERROR` em quem chama.
fn conversar(socket: &Path, linha: &str) -> Result<String, FalhaDeConversa> {
    let stream = UnixStream::connect(socket).map_err(FalhaDeConversa::em("conectar"))?;
    // A assinatura pode demorar: o app faz rede E mostra o diálogo de PIN/OTP,
    // que o usuário leva segundos para preencher. Um teto generoso evita
    // travar para sempre se o app morrer no meio.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));

    let mut escritor = stream.try_clone().map_err(FalhaDeConversa::em("enviar"))?;
    escritor
        .write_all(linha.as_bytes())
        .and_then(|()| escritor.flush())
        .map_err(FalhaDeConversa::em("enviar"))?;

    let mut leitor = BufReader::new(stream);
    let mut resp = String::new();
    leitor
        .read_line(&mut resp)
        .map_err(FalhaDeConversa::em("receber"))?;
    if resp.trim().is_empty() {
        // O app fechou a conexão sem responder: morreu, ou foi fechado, com o
        // pedido na mão.
        return Err(FalhaDeConversa {
            etapa: "receber",
            erro: None,
        });
    }
    Ok(resp)
}

/// Uma linha no diag do módulo. `assinatura.sem_app` quando nem deu para
/// conectar (o caso da issue 26: o app fechado, e o certificado ainda listado
/// porque quem lista é o módulo); `assinatura.sem_resposta` quando o app
/// aceitou e não devolveu nada.
fn registrar_falha(
    diag: &Path,
    socket: &Path,
    hospedeiro: Option<&str>,
    algoritmo: Algoritmo,
    falha: &FalhaDeConversa,
) {
    let (evento, dica) = if falha.etapa == "conectar" {
        (
            "assinatura.sem_app",
            "o remoteid-app não está no ar: abra o app e tente de novo",
        )
    } else {
        (
            "assinatura.sem_resposta",
            "o remoteid-app aceitou o pedido e não respondeu",
        )
    };
    Diag::anexar(diag).evento(
        evento,
        json!({
            "socket": socket.display().to_string(),
            "etapa": falha.etapa,
            "erro": falha.erro.as_ref().map(|e| format!("{:?}", e.kind())),
            "hospedeiro": hospedeiro,
            "algoritmo": algoritmo.nome(),
            "dica": dica,
        }),
    );
}

/// Traduz o erro do app para um código Cryptoki que o hospedeiro entenda.
fn traduzir_erro(codigo: CodigoErro) -> CK_RV {
    match codigo {
        // O usuário fechou o diálogo de PIN/OTP: o poppler mostra "cancelado".
        CodigoErro::Cancelado => CKR_FUNCTION_CANCELED,
        // O servidor recusou PIN/OTP. Fora da lista formal do `C_Sign`, mas é o
        // código que NSS e SunPKCS11 sabem mostrar como "PIN incorreto"; um
        // `CKR_FUNCTION_FAILED` virava stack trace no PJeOffice (issue 21).
        CodigoErro::FatorRecusado => CKR_PIN_INCORRECT,
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

#[cfg(test)]
mod tests {
    use super::*;

    // Os testes de env serializam entre si (o cargo roda os testes da mesma
    // binária em paralelo), no mesmo padrão do `socket.rs` do daemon.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Roda `f` com as três variáveis que `caminho_socket` lê nos valores
    /// dados (`None` = ausente), e restaura tudo depois.
    fn com_env(socket: Option<&str>, test_url: Option<&str>, xdg: Option<&str>, f: impl FnOnce()) {
        let _guarda = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vars = [
            ("REMOTEID_SOCKET", socket),
            ("TEST_URL", test_url),
            ("XDG_RUNTIME_DIR", xdg),
        ];
        let salvos: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in salvos {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn remoteid_socket_vence_tudo() {
        // É o override do Flatpak: com ele setado, nem o modo de teste nem o
        // XDG importam. Vazio conta como ausente.
        com_env(
            Some("/x/a.sock"),
            Some("http://mock"),
            Some("/run/u"),
            || {
                assert_eq!(caminho_socket(), PathBuf::from("/x/a.sock"));
            },
        );
        com_env(Some(""), None, Some("/run/u"), || {
            assert_eq!(caminho_socket(), PathBuf::from("/run/u/remoteid.sock"));
        });
    }

    #[test]
    fn em_teste_o_socket_mora_no_dir_de_teste() {
        com_env(None, Some("http://mock"), Some("/run/u"), || {
            assert_eq!(
                caminho_socket(),
                PathBuf::from(remoteid_caminhos::DIR_TESTE).join("remoteid.sock")
            );
        });
    }

    #[test]
    fn sem_xdg_cai_em_run_user_do_uid_real() {
        // XDG ausente ou vazio: `/run/user/<uid>`, com o uid DESTE processo.
        let esperado = PathBuf::from(format!("/run/user/{}/remoteid.sock", uid_real()));
        com_env(None, None, None, || {
            assert_eq!(caminho_socket(), esperado.clone())
        });
        com_env(None, None, Some(""), || {
            assert_eq!(caminho_socket(), esperado.clone())
        });
    }

    /// O uid do processo por outro caminho que não o `/proc/self/status`
    /// que a função testada lê: os metadados de `/proc/self`.
    fn uid_real() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    #[test]
    fn uid_e_o_do_processo() {
        assert_eq!(uid(), uid_real());
    }

    #[test]
    fn comm_e_o_nome_deste_processo() {
        // É o "Solicitado por <host>" do diálogo. Tem de ser o `comm` de
        // verdade (a binária de teste), nunca vazio nem inventado.
        let comm = std::fs::read_to_string("/proc/self/comm")
            .unwrap()
            .trim()
            .to_string();
        assert!(!comm.is_empty());
        assert_eq!(comm_do_processo().as_deref(), Some(comm.as_str()));
    }

    /// Um diretório só deste teste, para o diag e o socket.
    fn dir_do_teste(nome: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rid-cliente-{nome}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn linhas_do_diag(caminho: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(caminho)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn sem_app_no_ar_falha_com_device_error_e_deixa_rastro() {
        // O caso da issue 26: a janela foi fechada, o socket sumiu, e o
        // hospedeiro só via CKR_DEVICE_ERROR, sem linha em diag nenhum.
        let dir = dir_do_teste("sem-app");
        let socket = dir.join("nao-existe.sock");
        let diag = dir.join("diag").join("modulo-pkcs11.jsonl");

        let r = assinar_por(&socket, &diag, Algoritmo::Sha256, &[7u8; 32]);
        assert_eq!(r, Err(CKR_DEVICE_ERROR));

        let linhas = linhas_do_diag(&diag);
        assert_eq!(linhas.len(), 1, "{linhas:?}");
        let l = &linhas[0];
        assert_eq!(l["evento"], "assinatura.sem_app");
        assert_eq!(l["etapa"], "conectar");
        assert_eq!(l["erro"], "NotFound");
        assert_eq!(l["socket"], socket.display().to_string());
        assert_eq!(l["algoritmo"], Algoritmo::Sha256.nome());
        assert_eq!(l["hospedeiro"], comm_do_processo().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn app_que_fecha_sem_responder_vira_sem_resposta() {
        // O app aceitou e foi embora com o pedido na mão: outro diagnóstico,
        // e por isso outro evento.
        let dir = dir_do_teste("sem-resposta");
        let socket = dir.join("app.sock");
        let diag = dir.join("modulo-pkcs11.jsonl");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let app = std::thread::spawn(move || {
            let (fluxo, _) = listener.accept().unwrap();
            let mut linha = String::new();
            BufReader::new(&fluxo).read_line(&mut linha).unwrap();
            // Recebeu o pedido inteiro e fecha sem responder.
            assert!(linha.contains("digest_b64"), "{linha}");
        });

        let r = assinar_por(&socket, &diag, Algoritmo::Cru, &[1u8; 34]);
        app.join().unwrap();
        assert_eq!(r, Err(CKR_DEVICE_ERROR));

        let linhas = linhas_do_diag(&diag);
        assert_eq!(linhas.len(), 1, "{linhas:?}");
        assert_eq!(linhas[0]["evento"], "assinatura.sem_resposta");
        assert_eq!(linhas[0]["etapa"], "receber");
        assert!(linhas[0]["erro"].is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn falhas_seguidas_vao_para_o_mesmo_arquivo() {
        let dir = dir_do_teste("seguidas");
        let socket = dir.join("nao-existe.sock");
        let diag = dir.join("modulo-pkcs11.jsonl");
        for _ in 0..3 {
            let _ = assinar_por(&socket, &diag, Algoritmo::Sha256, &[0u8; 32]);
        }
        assert_eq!(linhas_do_diag(&diag).len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fator_recusado_vira_pin_incorrect() {
        assert_eq!(traduzir_erro(CodigoErro::FatorRecusado), CKR_PIN_INCORRECT);
    }

    #[test]
    fn cancelamento_do_dialogo_vira_function_canceled() {
        // É o código que faz o poppler dizer "cancelado" em vez de "falhou":
        // o usuário fechou o diálogo de PIN/OTP de propósito.
        assert_eq!(traduzir_erro(CodigoErro::Cancelado), CKR_FUNCTION_CANCELED);
        for outro in [
            CodigoErro::ErroServidor,
            CodigoErro::ErroRede,
            CodigoErro::EntradaInvalida,
            CodigoErro::NaoPreparado,
            CodigoErro::ErroInterno,
            CodigoErro::RequisicaoInvalida,
        ] {
            assert_eq!(traduzir_erro(outro), CKR_FUNCTION_FAILED);
        }
    }
}
