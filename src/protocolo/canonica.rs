//! A forma canônica do corpo, que é o que o `Bearer` assina.
//!
//! Regra decompilada do app oficial de macOS (`FUN_10002515b` e as funções de
//! tipo do jsoncpp em volta):
//!
//! - objeto: chaves em ordem alfabética, concatenando o resultado de cada valor;
//! - string e número: o valor;
//! - bool `true`: o **nome da chave**, não a palavra "true";
//! - bool `false` e null: nada;
//! - array: cada elemento, sem chave (um `true` num array não escreve nada).
//!
//! Consequência: string vazia e chave ausente dão o mesmo resultado, e por isso
//! um `Bearer` certo não prova que o corpo está certo (ver o `algorithm` em
//! [`super::requisicao::request_hash`]).

use serde_json::Value;

pub fn canonica(corpo: &Value) -> String {
    let mut saida = String::new();
    escrever(&mut saida, corpo, None);
    saida
}

fn escrever(saida: &mut String, valor: &Value, chave: Option<&str>) {
    match valor {
        Value::Object(campos) => {
            let mut chaves: Vec<&String> = campos.keys().collect();
            chaves.sort();
            for k in chaves {
                escrever(saida, &campos[k], Some(k));
            }
        }
        Value::Array(itens) => {
            for item in itens {
                escrever(saida, item, None);
            }
        }
        Value::Bool(true) => saida.push_str(chave.unwrap_or("")),
        Value::Bool(false) | Value::Null => {}
        Value::String(s) => saida.push_str(s),
        Value::Number(n) => saida.push_str(&n.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::canonica;
    use serde_json::json;

    #[test]
    fn bool_true_escreve_o_nome_da_chave() {
        assert_eq!(canonica(&json!({"push": true})), "push");
        assert_eq!(canonica(&json!({"push": false, "x": null})), "");
        assert_eq!(canonica(&json!({"a": [true, "v"]})), "v");
    }

    #[test]
    fn ordem_alfabetica_e_recursao() {
        let corpo = json!({"z": "Z", "hashArray": [{"id": 1, "hash": "H"}], "a": "A"});
        assert_eq!(canonica(&corpo), "AH1Z");
    }
}
