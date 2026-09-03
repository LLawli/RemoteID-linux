// Dumpa bytes/pointers ao redor de um endereço.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class dumpmem extends GhidraScript {
    private void out(String s) { println("@@ " + s); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long base = Long.parseUnsignedLong(args[0].replace("0x",""), 16);
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        for (int i = -4; i < n; i++) {
            long a = base + 8L*i;
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(Long.toHexString(a));
                long v = mem.getLong(addr);
                String tag = "";
                if (v > 0x100000000L && v < 0x110000000L) {
                    Address ta = currentProgram.getAddressFactory().getAddress(Long.toHexString(v));
                    Function f = fm.getFunctionContaining(ta);
                    if (f != null) tag = "  -> FUNC " + f.getName() + " @ " + f.getEntryPoint();
                }
                out(String.format("0x%x: 0x%016x %s", a, v, tag));
            } catch (Exception e) { out("0x" + Long.toHexString(a) + ": (bad)"); }
        }
    }
}
