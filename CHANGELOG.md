# Changelog

Todas as mudanças visíveis para quem usa ficam aqui. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/), e o projeto usa
[versionamento semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Adicionado

- A extensão `dev.lukakuuhaku.Ancora.Driver.RemoteID` do Âncora, com a janela
  do RemoteID e o módulo PKCS#11.
- O módulo PKCS#11 assina sozinho, com só o serviço do Âncora no ar: mostra o
  certificado da carteira como token e, quando a sessão em cache não vale
  mais, abre uma janela que pede o código do autenticador.
- O token traz a cadeia de autoridades do certificado, baixada do
  `caIssuers`, para os assinadores que montam a cadeia pelo token.
- Um navegador aberto vê o certificado quando a conta é preparada ou trocada,
  sem precisar ser reiniciado.
- `remoteid entrar <email>` entra na conta, registra a máquina e baixa a
  carteira, com a senha pelo stdin.
- `remoteid assinar` assina o que chega pela entrada padrão e devolve um
  `.p7s` na política AD-RB da ICP-Brasil (destacado, ou com `--anexar` o
  documento dentro), ou com `--cru` só a assinatura RSA. O código do
  autenticador é pedido na mesma janela do módulo, ou no terminal quando o
  programa roda fora do Flatpak.
- `remoteid harness` testa o fluxo com a conta entrada e grava um relatório
  sem senha, PIN, OTP nem o titular.
- A janela do RemoteID: entrar na conta, o certificado que assina como um
  cartão com o estado da sessão (aberta até que horas, ou pedindo o código),
  trocar de certificado passando o cartão, detalhes com a cadeia e a conta,
  reautorizar e sair, com "Desfazer". Acompanha as assinaturas feitas com ela
  aberta.
- A senha da conta fica no chaveiro do sistema: a assinatura pede só o código
  do autenticador. Sem chaveiro, a senha fica cifrada no computador com um PIN
  de 4 a 6 dígitos, criado ao entrar e pedido uma vez por aplicativo aberto;
  cinco PINs errados seguidos apagam a senha e saem da conta.
