# A engenharia reversa do RemoteID

O protocolo do RemoteID não tem documentação pública: foi reconstruído dos
aplicativos oficiais de macOS (desktopID 2.2.0.1) e de Windows, e confirmado
contra o servidor de produção entre agosto e setembro de 2026, no
RemoteID-linux. Estes são os registros desse trabalho, trazidos da v0.3.2 como
estavam, para quem precisar entender o protocolo ou reimplementá-lo.

| documento | o que tem |
|---|---|
| [PROTOCOLO.md](PROTOCOLO.md) | os aplicativos oficiais por dentro, as bases de URL, os endpoints, e como cada coisa foi extraída dos binários |
| [PAYLOADS.md](PAYLOADS.md) | o corpo de cada requisição e o que se lê de cada resposta, a canonicalização que o `Bearer` assina, o campo `algorithm` e o formato do `sessionToken` |
| [ARQUITETURA-SO.md](ARQUITETURA-SO.md) | como o aplicativo oficial mostra o certificado ao navegador: o módulo PKCS#11, o socket e o processo que fala com a Certisign |
| [OAUTH.md](OAUTH.md) | o login web com certificado (OAuth2 com PKCE), que não é o caminho deste aplicativo |

## O que mudou depois

Os textos ficaram como foram escritos, e às vezes uma seção corrige a anterior
(a seção 6b do PROTOCOLO.md desfaz a leitura inicial de que a chave desce para
a máquina). O que se soube depois deles:

- **O "PIN" do `tokensessao` é a senha da conta**, a mesma do login, e não um
  PIN do certificado. O campo do protocolo continua `pin`; o fator que
  autentica de verdade é o OTP.
- A aprovação por celular (push) foi lida no binário e implementada no
  RemoteID-linux, mas nunca passou por uma conta real. Esta versão não a tem.
- O "roadmap do app GTK" do ARQUITETURA-SO.md foi construído: o módulo, a
  janela e o motor estão neste repositório, e o socket entre eles deu lugar ao
  motor dentro do próprio módulo ([../arquitetura.md](../arquitetura.md)).
- Os valores de exemplo que identificariam uma pessoa (CPF, serial de
  certificado) foram trocados por sintéticos.

## Onde o protocolo está no código

| parte | arquivo |
|---|---|
| as requisições, uma função por endpoint | `src/protocolo/requisicao.rs` |
| a leitura das respostas, e "HTTP 200 pode ser erro" | `src/protocolo/resposta.rs` |
| a canonicalização do corpo | `src/protocolo/canonica.rs` |
| o `Bearer`: a assinatura da canônica com a chave da instalação | `src/cripto.rs` |
| o campo `algorithm` e os tamanhos que o servidor aceita | `src/protocolo/algoritmo.rs` |
| as mensagens de erro do servidor e de quem é a culpa | `src/protocolo/classificacao.rs` |
| URLs, `USER_AGENT` e o nome da aplicação | `src/protocolo/mod.rs` |

Cada uma é conferida byte a byte contra a v0.3.2 por `tests/paridade.rs`, com
as fixtures que o `paridade/` grava rodando o código antigo.
