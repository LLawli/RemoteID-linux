// Lista quem referencia um ENDEREÇO DE DADO e decompila os referenciadores.
//
// Complementa findstr.java: aquele parte do texto do literal, este parte do
// endereço. Serve quando o literal é curto ou deduplicado pelo linker e a busca
// por texto devolve ocorrências demais, e quando o endereço já veio de
// `strings -t x` (offset de ARQUIVO; no Mach-O do desktopID o endereço virtual
// é 0x100000000 + offset, ver docs/PROTOCOLO.md).
//
// Uso: tools/ghidra/run.sh xrefsto.java 0x1005dba1c 0x1005dba7c
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class xrefsto extends GhidraScript {
    private void out(String s) { println("@@ " + s); }

    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        Set<Function> alvos = new LinkedHashSet<>();

        for (String a : getScriptArgs()) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            out("##### xrefs para " + addr);
            int n = 0;
            for (ReferenceIterator it = rm.getReferencesTo(addr); it.hasNext(); ) {
                Reference r = it.next();
                Function f = fm.getFunctionContaining(r.getFromAddress());
                out("  " + r.getReferenceType() + " de " + r.getFromAddress()
                    + (f != null ? "  em " + f.getName() + " @ " + f.getEntryPoint() : ""));
                if (f != null) alvos.add(f);
                n++;
            }
            if (n == 0) out("  (nenhum xref direto)");
        }
        for (Function f : alvos) {
            out("===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            DecompileResults res = di.decompileFunction(f, 180, mon);
            String c = (res != null && res.decompileCompleted())
                     ? res.getDecompiledFunction().getC() : "(falha ao decompilar)";
            for (String ln : c.split("\n")) out("  " + ln);
        }
    }
}
