//! Camada de serviço do RemoteID-linux — motor + socket UNIX (SEM UI).
//!
//! Depois da unificação de 03/09/2026 ([[remoteid-app-unificado]]) este crate
//! **não é mais um daemon separado** (o nome ficou por histórico): virou a lib
//! consumida in-process pelo app `remoteid-app` (crate `remoteid-gtk`). Ela é
//! dona do `state.json`, única a falar com o RemoteID, e expõe o [`servico::Servico`]
//! (que o app aciona direto) e os utilitários de [`socket`] (que o app integra
//! ao loop do GTK para atender o módulo PKCS#11).
//!
//! É **livre de GTK**: o diálogo de PIN/OTP mora no app (`remoteid-gtk`), e
//! aqui só existe o trait [`prompter::Prompter`] (com [`prompter::FatoresFixos`]
//! para os testes). Assim os testes de integração exercitam [`servico::Servico`]
//! sem compilar GTK.
//!
//! Quem atende o socket é o app (integrado ao loop do GTK); [`socket`] guarda
//! só `caminho_padrao` + `bind_manual`. O socket-activation do systemd foi
//! abandonado na unificação (não cruza limpo a fronteira do sandbox Flatpak).

pub mod prompter;
pub mod servico;
pub mod socket;

// O protocolo saiu para um crate-folha próprio (`remoteid-protocolo`, sem GTK)
// para que a janela GTK e o futuro `C_Sign` do módulo PKCS#11 (um cdylib que
// não pode linkar GTK) falem o mesmo protocolo sem depender do daemon inteiro.
// Re-exportado aqui para `crate::protocolo::...` continuar resolvendo em todo o
// daemon e nos testes de integração, sem tocar em cada `use`.
pub use remoteid_protocolo as protocolo;
