// Acha função pelo nome (substring, case-insensitive) e decompila.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class findfn extends GhidraScript {
    private void out(String s) { println("@@ " + s); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String needle = args[0].toLowerCase();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            String n = f.getName();
            if (n.toLowerCase().contains(needle)) {
                out("===== " + n + " @ " + f.getEntryPoint() + " =====");
                DecompileResults res = di.decompileFunction(f, 180, mon);
                String c = (res != null && res.decompileCompleted())
                         ? res.getDecompiledFunction().getC() : "(falha)";
                for (String ln : c.split("\n")) out("  " + ln);
            }
        }
    }
}
