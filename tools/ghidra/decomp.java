import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class decomp extends GhidraScript {
    private void out(String s) { println("@@ " + s); }

    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        String[] args = getScriptArgs();
        FunctionManager fm = currentProgram.getFunctionManager();
        for (String a : args) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function fn = fm.getFunctionContaining(addr);
            if (fn == null) { out("### " + a + ": sem funcao"); continue; }
            DecompileResults res = di.decompileFunction(fn, 90, new ConsoleTaskMonitor());
            out("\n===== " + fn.getName() + " @ " + a + " =====");
            if (res != null && res.decompileCompleted())
                for (String ln : res.getDecompiledFunction().getC().split("\n")) out("  " + ln);
            else
                out("(falha ao decompilar)");
        }
    }
}
