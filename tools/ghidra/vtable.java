// Explora uma vtable C++: mostra os ponteiros vizinhos (os outros métodos da
// mesma classe) e quem referencia a vtable (tipicamente o construtor).
//
// O app é todo estratégia virtual, então achar a função que monta um payload
// raramente dá o caller: a chamada vem de uma vtable. Este script fecha esse
// salto.
//
// Uso: tools/ghidra/run.sh vtable.java 0x100624428 [janela]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class vtable extends GhidraScript {
    private void out(String s) { println("@@ " + s); }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address addr = currentProgram.getAddressFactory().getAddress(args[0]);
        int win = args.length > 1 ? Integer.parseInt(args[1]) : 12;
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Memory mem = currentProgram.getMemory();

        out("##### vtable em torno de " + addr);
        for (int i = -win; i <= win; i++) {
            Address slot = addr.add((long) i * 8);
            long v;
            try { v = mem.getLong(slot); } catch (MemoryAccessException e) { continue; }
            Address t = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            Function f = fm.getFunctionContaining(t);
            String marca = (i == 0) ? " <== " : "     ";
            out(marca + slot + " -> " + t
                + (f != null ? "  " + f.getName() : (v == 0 ? "  (null)" : "  (não é função)")));
            // Quem referencia este slot? Um xref à base da vtable é o construtor.
            for (ReferenceIterator it = rm.getReferencesTo(slot); it.hasNext(); ) {
                Reference r = it.next();
                Function cf = fm.getFunctionContaining(r.getFromAddress());
                out("        <- " + r.getReferenceType() + " de " + r.getFromAddress()
                    + (cf != null ? "  em " + cf.getName() + " @ " + cf.getEntryPoint() : ""));
            }
        }
    }
}
