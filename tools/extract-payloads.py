#!/usr/bin/env python3
"""Reconstrói os payloads de cada endpoint a partir do binário oficial de macOS.

Como: o app usa jsoncpp (chaves JSON = literais char*) e QtNetwork. Para cada
endpoint (string UTF-32 em __const), acha a instrução que o referencia, delimita
a função pelos `ret` ao redor, e resolve toda string que a função carrega via
`lea` rip-relative (__cstring ASCII / __const UTF-32). A ordem no código é
path -> campos do request -> campos do response.

Uso:
  llvm-objdump -d --x86-asm-syntax=intel --no-show-raw-insn <binario> > disasm.txt
  python3 extract-payloads.py <binario> disasm.txt

Os endereços das seções (__cstring/__const) são do build 2.2.0.1; para outro
build, reconfira com `llvm-objdump --macho --section-headers`.
"""
import re, sys, struct, bisect
BIN, DIS = sys.argv[1], sys.argv[2]
data=open(BIN,'rb').read()
BASE=0x100000000
CSTR=(0x1002aa600,0x1e25f); CONST=(0x1002c8880,0x34de88); CONST2=(0x1006209f0,0x2e040)
def rd_ascii(a):
    o=a-BASE; e=data.find(b'\x00',o)
    if e<0 or e-o>500: return None
    try: s=data[o:e].decode('utf-8')
    except: return None
    return s if s.isprintable() else None
def rd_wide(a):
    o=a-BASE; out=[]
    for i in range(o,min(o+2000,len(data)),4):
        cp=struct.unpack_from('<I',data,i)[0]
        if cp==0: break
        if cp>0x10FFFF: return None
        out.append(cp)
    if not out: return None
    try: s=''.join(map(chr,out))
    except: return None
    return s if s.isprintable() else None
def resolve(a):
    if CSTR[0]<=a<CSTR[0]+CSTR[1]: return rd_ascii(a)
    if CONST[0]<=a<CONST[0]+CONST[1] or CONST2[0]<=a<CONST2[0]+CONST2[1]:
        return rd_wide(a) or rd_ascii(a)
    return None

addr_re=re.compile(r'^([0-9a-f]+):\s+(\S+)')
ref_re=re.compile(r'## (0x[0-9a-f]+)')
insns=[]  # (addr, mnem, ref)
for ln in open(DIS):
    m=addr_re.match(ln)
    if not m: continue
    a=int(m.group(1),16); mn=m.group(2)
    r=ref_re.search(ln)
    insns.append((a, mn, int(r.group(1),16) if r else None))
addrs=[a for a,_,_ in insns]
def window(R):
    i=bisect.bisect_left(addrs,R)
    # para trás até depois de um ret
    lo=i
    while lo>0 and insns[lo-1][1]!='ret': lo-=1
    hi=i
    while hi<len(insns) and insns[hi][1]!='ret': hi+=1
    return insns[lo:hi+1]
def strings_in(win):
    out=[]
    for a,mn,ref in win:
        if ref is not None:
            s=resolve(ref)
            if s and (len(s)>=2 or s in '{}[]'): out.append(s)
    return out

def find_ep(full):
    a=data.find(full.encode("utf-32-le")); return a+BASE if a>=0 else None

eps=["/api/manager/usuarios/login/usrsenha","/create","/requestAuthorization/",
"/isAuthorized/","/isDone/","/listCertificates/","/listHierarchies",
"/maintenanceDevices/","/push/","/cancelAuthorization/",
"/api/manager/desktopid/","/api/signature/tokensessao",
"/api/signature/requestHashSessionSignature"]

# blacklist de ruído (mensagens de erro de libs)
NOISE=('allocator','Unreachable','wstring_convert','Connection error','optional.hpp',
'streambuf','jsoncpp','readValue','JSON document','Syntax error','stackLimit',
'Missing','no read','no write','putback','write area','bad seek','already open',
'operator','seek_impl','initialized_','addComment','shared_ptr','NSt3','exceeds',
'Erro de conexão',' | (',': Un','_ZT','boost','char_traits','basic_string')
def clean(strs):
    out=[]
    for s in strs:
        if any(n in s for n in NOISE): continue
        if s in out: continue
        out.append(s)
    return out

for full in eps:
    ep=find_ep(full)
    if ep is None: print(f"\n##### {full}: nao achado"); continue
    refs=[a for a,mn,r in insns if r==ep]
    print(f"\n##### {full}  refs={[hex(x) for x in refs]}")
    for R in refs:
        w=window(R)
        strs=clean(strings_in(w))
        print(f"   janela {hex(w[0][0])}..{hex(w[-1][0])} ({len(w)} insn)")
        print("   ->", strs[:50])
