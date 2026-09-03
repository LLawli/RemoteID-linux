// Procura símbolos por substring de nome (Ghidra pode ter demangling)
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class sym extends GhidraScript {
    private void out(String s) { println("@@ " + s); }
    public void run() throws Exception {
        String needle = getScriptArgs()[0];
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getAllSymbols(true);
        int count = 0;
        while (it.hasNext()) {
            Symbol s = it.next();
            String n = s.getName();
            if (n.contains(needle)) {
                out(String.format("%s @ %s  [%s]", n, s.getAddress(), s.getSymbolType()));
                count++;
                if (count > 200) { out("... (>200)"); break; }
            }
        }
        out("total: " + count);
    }
}
