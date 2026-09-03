# Ferramentas de engenharia reversa

Recuperam o protocolo do binário oficial de macOS (ver docs/PROTOCOLO.md §8 para
extrair o binário para `vendor/`).

## extract-payloads.py
Reconstrói os campos de cada endpoint a partir das literais e do disassembly.
```
llvm-objdump -d --x86-asm-syntax=intel --no-show-raw-insn <bin> > disasm.txt
python3 tools/extract-payloads.py <bin> disasm.txt
```

## ghidra/decompile.sh
Decompila funções por endereço (pseudo-C) com Ghidra headless num contêiner.
```
tools/ghidra/decompile.sh 0x100065558 0x1000767a8
```
Endereços vêm de `llvm-nm <bin> | c++filt` ou dos xrefs do extract-payloads.
Precisa da imagem `docker.io/blacktop/ghidra` (≈1.3 GB) e do binário em vendor/.

Achados-chave já documentados em docs/PAYLOADS.md (auth por assinatura,
canonicalização do corpo, formatos).

## ghidra/run.sh — o wrapper que reusa o projeto

`decompile.sh` é atalho para `run.sh decomp.java`. O `run.sh` roda qualquer
GhidraScript sobre o binário e **reusa** o projeto em `vendor/ghidra-proj`: a
análise leva alguns minutos e só acontece na primeira vez.

```
tools/ghidra/run.sh <script.java> [args...]
```

### Qual script usar

| pergunta | script |
|---|---|
| que função monta o payload com a chave `X`? | `findstr.java X` |
| quem referencia o dado neste endereço? | `xrefsto.java 0x1005dba1c` |
| quem chama esta função? | `callers.java 0x1000763a2` |
| a chamada é virtual; para onde ela vai? | `vtable.java 0x100624428 8` |
| o C decompilado engoliu um argumento | `disasm.java 0x100067890 55` |
| decompila estes endereços | `decompile.sh 0x100077120` |
| tem função no Ghidra cujo NOME contém X? | `findfn.java <substring>` |
| que símbolos casam com Y? | `sym.java <substring>` |
| dá pra achar a vtable a partir do typeinfo? | `vtof.java 0x100623b00` |
| que ponteiros/funções estão neste endereço? | `dumpmem.java 0x100623b00 [n=16]` |

Os quatro últimos apareceram na análise de 03/09/2026 do
`nomeAplicacaoDesktop`. `findfn` e `dumpmem` foram os que resolveram (nomear a
função pelo nome interno do Ghidra e listar pointers com resolução de "isto é
uma FUNC?"); `sym` e `vtof` ficam como referência pra binário stripped, onde a
maior parte dos nomes de símbolo interno não sobrevive.

### Três armadilhas que custaram tempo

1. **Codificação.** Chaves de JSON e mensagens são ASCII (`std::string`);
   endpoints, nós do `identity.xml` e valores de `AuthorizationMode` são
   UTF-32LE (`std::wstring`). O `findstr.java` procura nas duas; o `strings`
   precisa de `-eL` para a segunda, e de `-n 3` para achar `pin` e `otp`.
2. **Literal deduplicado.** O linker funde literais iguais, então a vizinhança
   de uma string não prova nada sobre qual payload a usa. Decompile antes de
   concluir. Endereço de `strings -t x` é offset de ARQUIVO: some 0x100000000
   para o endereço virtual.
3. **Argumento engolido.** `std::wstring::assign` recebe o valor por
   registrador e o decompilador imprime `assign(dst)`, sem o valor. Só o
   assembly mostra o `LEA` do literal. Foi assim que se descobriu que o
   `statusCelular` grava `AuthorizationMode = "local"` incondicionalmente.

### Pegadinha do podman rootless

O Ghidra grava o dono dentro do projeto e recusa abrir projeto de outro usuário
(`NotOwnerException`), então o `run.sh` usa `--userns=keep-id`. Se o projeto
ficar com dono errado, apague `vendor/ghidra-proj`: ele é descartável.
