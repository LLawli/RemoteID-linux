#!/usr/bin/env python3
"""Gera `crates/remoteid-pkcs11/src/stubs.rs` a partir das bindings do cryptoki-sys.

A `CK_FUNCTION_LIST` tem 68 ponteiros e nenhum deles pode ser NULL: o p11-kit e
o NSS chamam sem checar. As funções que este módulo ainda não implementa
precisam, portanto, existir como stub com a assinatura EXATA do header.

O compilador já garante que a assinatura bate (o literal da struct em `lista.rs`
não compila com tipo errado). Este gerador existe só para não digitar 50
assinaturas na mão.

    python3 tools/gerar-stubs-pkcs11.py > crates/remoteid-pkcs11/src/stubs.rs
"""
import glob
import re
import sys

# As funções implementadas de verdade não ganham stub.
IMPLEMENTADAS = {
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo",
    "C_GetMechanismList", "C_GetMechanismInfo",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
    "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal",
    "C_GetAttributeValue",
    "C_Login", "C_Logout",
    "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal",
    "C_EncryptInit", "C_Encrypt",
}

alvo = sys.argv[1] if len(sys.argv) > 1 else "x86_64-unknown-linux-gnu"
caminhos = glob.glob(
    f"{glob.escape(sys.path[0])}/../target/**/cryptoki-sys-*/src/bindings/{alvo}.rs",
    recursive=True,
) or glob.glob(
    f"/home/*/.cargo/registry/src/*/cryptoki-sys-*/src/bindings/{alvo}.rs"
)
if not caminhos:
    sys.exit("bindings do cryptoki-sys não encontradas; rode `cargo fetch` antes")
fonte = open(sorted(caminhos)[-1]).read()

# A ordem dos campos da CK_FUNCTION_LIST é a ordem canônica das funções.
struct = re.search(r"pub struct CK_FUNCTION_LIST \{(.*?)\n\}", fonte, re.S).group(1)
ordem = re.findall(r"pub (C_\w+):", struct)

# `pub type CK_C_Nome = Option<unsafe extern "C" fn(args) -> CK_RV>;`
aliases = {}
for m in re.finditer(
    r"pub type CK_C_(\w+) =\s*::std::option::Option<\s*unsafe extern \"C\" fn\((.*?)\)\s*->\s*CK_RV,?\s*>;",
    fonte,
    re.S,
):
    args = [a.split(":", 1)[1].strip().rstrip(",") for a in
            re.findall(r"arg\d+: [^,]+(?:,|$)", " ".join(m.group(2).split()))]
    aliases["C_" + m.group(1)] = args

print('//! Stubs das funções Cryptoki que este módulo ainda não implementa.')
print('//!')
print('//! ARQUIVO GERADO por `tools/gerar-stubs-pkcs11.py`. Não editar à mão.')
print('//!')
print('//! Nenhum ponteiro da `CK_FUNCTION_LIST` pode ser NULL — o p11-kit e o NSS')
print('//! chamam sem checar —, então toda função existe, e a que não implementamos')
print('//! devolve `CKR_FUNCTION_NOT_SUPPORTED`, que é o que a especificação manda.')
print()
print("#![allow(non_snake_case)]")
# Estas funções não desreferenciam nada: exigir uma seção `# Safety` em cada
# uma seria 51 blocos de comentário dizendo "não faz nada".
print("#![allow(clippy::missing_safety_doc)]")
print()
print("use cryptoki_sys::*;")
faltando = []
for nome in ordem:
    if nome in IMPLEMENTADAS:
        continue
    if nome not in aliases:
        faltando.append(nome)
        continue
    args = ", ".join(f"_: {t}" for t in aliases[nome])
    print()
    print(f"pub unsafe extern \"C\" fn {nome}({args}) -> CK_RV {{")
    print("    CKR_FUNCTION_NOT_SUPPORTED")
    print("}")
if faltando:
    sys.exit(f"sem alias para: {faltando}")
