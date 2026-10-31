//! O que os testes de integração dividem: o servidor falso.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use remoteid::protocolo::Servidor;

/// O servidor falso (`remoteid-mock`), morto quando o teste acaba.
pub struct Mock {
    processo: Child,
    pub url: String,
}

impl Mock {
    pub fn subir() -> Mock {
        let mut processo = Command::new(env!("CARGO_BIN_EXE_remoteid-mock"))
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut url = String::new();
        BufReader::new(processo.stdout.take().unwrap())
            .read_line(&mut url)
            .unwrap();
        Mock {
            processo,
            url: url.trim().to_string(),
        }
    }

    pub fn servidor(&self) -> Servidor {
        Servidor::falso(&self.url)
    }

    /// Esquece as sessões, como o servidor real faz quando elas vencem.
    pub fn expirar_sessoes(&self) {
        ureq::post(format!("{}/_mock/expirar", self.url))
            .send_empty()
            .unwrap();
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
    }
}
