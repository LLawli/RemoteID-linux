// Encontra vtable a partir do endereço do typeinfo: procura o padrão
// [0][typeinfo_ptr][fn1][fn2]... Retorna endereço da vtable + as N primeiras
// funções.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class vtof extends GhidraScript {
    private void out(String s) { println("@@ " + s); }
    public void run() throws Exception {
        long ti = Long.parseUnsignedLong(getScriptArgs()[0].replace("0x",""), 16);
        byte[] pat = new byte[8];
        for (int i=0;i<8;i++) pat[i] = (byte)((ti >> (8*i)) & 0xff);
        Memory mem = currentProgram.getMemory();
        DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        Address a = mem.getMinAddress();
        int hits = 0;
        while (a != null) {
            a = mem.findBytes(a, pat, null, true, mon);
            if (a == null) break;
            out("hit typeinfo @ " + a);
            // função na próxima 8 bytes é vtable[2]
            long vtable = a.getOffset() - 8; // vtable starts 8 bytes before typeinfo slot
            for (int i=0;i<12;i++) {
                try {
                    Address slotA = currentProgram.getAddressFactory().getAddress(Long.toHexString(a.getOffset()+8*(i+1)));
                    long fp = mem.getLong(slotA);
                    if (fp == 0) break;
                    out(String.format("  vtable+%d = 0x%x", (i+1)*8, fp));
                } catch (Exception e) { break; }
            }
            hits++;
            a = a.add(1);
        }
        out("hits: " + hits);
    }
}
