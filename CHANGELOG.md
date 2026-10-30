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
  mais, abre uma janela que pede o PIN e o código do autenticador.
- O token traz a cadeia de autoridades do certificado, baixada do
  `caIssuers`, para os assinadores que montam a cadeia pelo token.
- Um navegador aberto vê o certificado quando a conta é preparada ou trocada,
  sem precisar ser reiniciado.
- `remoteid entrar <email>` entra na conta, registra a máquina e baixa a
  carteira, com a senha pelo stdin.
