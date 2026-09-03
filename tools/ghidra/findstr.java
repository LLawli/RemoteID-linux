// Acha as funções que referenciam uma string literal e decompila cada uma.
//
// É o caminho para responder "como o app monta este payload?": as chaves do
// JSON são literais no binário, então a função que referencia "nomeAplicacao-
// Desktop" é a que monta o corpo do tokensessao.
//
// Procura o literal nas DUAS codificações que o binário usa (ver
// docs/PROTOCOLO.md): ASCII (`std::string`, chaves de JSON e mensagens) e
// UTF-32LE (`std::wstring`, endpoints, nós do identity.xml e valores de
// AuthorizationMode). Procurar só em ASCII fazia nomes como
// "AuthorizationMode" e "otp" parecerem inexistentes.
//
// Uso: tools/ghidra/run.sh findstr.java nomeAplicacaoDesktop momento ...
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class findstr extends GhidraScript {
    // O headless mistura o log do Ghidra no stdout; todo output nosso sai
    // com este prefixo para o wrapper filtrar sem pegar ruído.
    private void out(String s) { println("@@ " + s); }

    /** Literal C terminado em NUL, na codificação pedida. */
    private byte[] pattern(String s, String enc) throws Exception {
        if (enc.equals("utf32le")) {
            byte[] b = new byte[(s.length() + 1) * 4];
            for (int i = 0; i < s.length(); i++) {
                int cp = s.charAt(i);
                b[i * 4] = (byte) (cp & 0xff);
                b[i * 4 + 1] = (byte) ((cp >> 8) & 0xff);
            }
            return b;   // os 4 bytes finais já são zero: o terminador
        }
        return (s + "\0").getBytes("UTF-8");
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();
        ReferenceManager rm = currentProgram.getReferenceManager();
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        Set<Function> alvos = new LinkedHashSet<>();

        for (String s : args) {
            out("##### string \"" + s + "\"");
            for (String enc : new String[] {"ascii", "utf32le"}) {
                byte[] pat = pattern(s, enc);
                Address a = mem.getMinAddress();
                while (a != null) {
                    a = mem.findBytes(a, pat, null, true, mon);
                    if (a == null) break;
                    out("  @ " + a + "  [" + enc + "]");
                    int n = 0;
                    for (ReferenceIterator it = rm.getReferencesTo(a); it.hasNext(); ) {
                        Reference r = it.next();
                        Function f = fm.getFunctionContaining(r.getFromAddress());
                        out("    xref " + r.getFromAddress()
                                + (f != null ? "  em " + f.getName() + " @ " + f.getEntryPoint() : ""));
                        if (f != null) alvos.add(f);
                        n++;
                    }
                    if (n == 0) out("    (sem xref: provável acesso por offset calculado)");
                    a = a.add(1);
                }
            }
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
