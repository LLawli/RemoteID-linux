// Decompila as funções que CHAMAM um endereço (ou a função que o contém).
//
// Complementa findstr.java: aquele acha quem monta um payload (pela chave do
// JSON), este sobe um nível e mostra quem PREENCHE os campos antes da chamada.
//
// Uso: tools/ghidra/run.sh callers.java 0x1000763a2 [0x...]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class callers extends GhidraScript {
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
            Function alvo = fm.getFunctionContaining(addr);
            out("##### callers de " + a
                + (alvo != null ? " (" + alvo.getName() + ")" : " (sem função)"));
            Address entry = alvo != null ? alvo.getEntryPoint() : addr;
            for (ReferenceIterator it = rm.getReferencesTo(entry); it.hasNext(); ) {
                Reference r = it.next();
                Function f = fm.getFunctionContaining(r.getFromAddress());
                out("  " + r.getReferenceType() + " de " + r.getFromAddress()
                    + (f != null ? "  em " + f.getName() + " @ " + f.getEntryPoint() : ""));
                if (f != null) alvos.add(f);
            }
            if (alvos.isEmpty()) out("  (nenhum caller direto: chamada por vtable?)");
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
