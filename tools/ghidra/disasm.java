// Lista as instruções de um intervalo, com o alvo de cada referência resolvido.
//
// Existe porque o decompilador às vezes ENGOLE o argumento de uma chamada
// (típico de `std::wstring::assign`, cujo valor chega por registrador): o C sai
// como `assign(dst)` sem dizer o quê. No assembly o `lea` do literal aparece.
//
// Uso: tools/ghidra/run.sh disasm.java 0x1000678a0 40
//      (endereço inicial e quantas instruções; padrão 40)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class disasm extends GhidraScript {
    private void out(String s) { println("@@ " + s); }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address addr = currentProgram.getAddressFactory().getAddress(args[0]);
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 40;
        Listing lst = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();

        out("##### disassembly de " + addr + " (" + n + " instruções)");
        Instruction ins = lst.getInstructionAt(addr);
        if (ins == null) ins = lst.getInstructionAfter(addr);
        for (int i = 0; i < n && ins != null; i++, ins = ins.getNext()) {
            StringBuilder sb = new StringBuilder();
            sb.append(ins.getAddress()).append("  ").append(ins.toString());
            // O que este operando aponta: literal, função, dado.
            for (Reference r : rm.getReferencesFrom(ins.getAddress())) {
                Address to = r.getToAddress();
                sb.append("   ; -> ").append(to);
                Data d = lst.getDataAt(to);
                if (d != null && d.getValue() != null) {
                    String v = String.valueOf(d.getValue());
                    if (v.length() > 60) v = v.substring(0, 60) + "...";
                    sb.append(" = ").append(v);
                }
                Function f = currentProgram.getFunctionManager().getFunctionAt(to);
                if (f != null) sb.append(" (").append(f.getName()).append(")");
            }
            out("  " + sb);
        }
    }
}
