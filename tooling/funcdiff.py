import struct, sys, hashlib, json
import macho

LC_FUNCTION_STARTS = 0x26

def uleb(b, o):
    r = 0; s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80): break
        s += 7
    return r, o

def func_starts(buf, info):
    ncmds = info['ncmds']; off = 32
    foff = fsize = None
    for _ in range(ncmds):
        cmd = struct.unpack_from('<I', buf, off)[0]
        cmdsize = struct.unpack_from('<I', buf, off+4)[0]
        if cmd == LC_FUNCTION_STARTS:
            foff, fsize = struct.unpack_from('<II', buf, off+8)
        off += cmdsize
        if cmdsize == 0: break
    if foff is None: return []
    base = info['segs'][0][1]  # vmaddr of first segment (__TEXT)
    starts = []; cur = base; o = foff; end = foff + fsize
    while o < end:
        d, o = uleb(buf, o)
        if d == 0: break
        cur += d
        starts.append(cur)
    return starts

def vm2off(info, vm):
    for name, vma, vmsz, fo, fsz in info['segs']:
        if vma <= vm < vma + vmsz and fsz > 0:
            return fo + (vm - vma)
    return None

def funcs(path):
    buf = open(path,'rb').read()
    info = macho.parse_macho(buf, 0)
    st = func_starts(buf, info)
    out = {}
    for i, vm in enumerate(st):
        endvm = st[i+1] if i+1 < len(st) else vm + 0x40
        o = vm2off(info, vm); e = vm2off(info, endvm)
        if o is None: continue
        if e is None: e = o + (endvm - vm)
        out[vm] = (buf[o:e], endvm - vm)
    return buf, info, out

def strings(path, secs=('__cstring','__os_log','__ustring'), minlen=6):
    import cstr
    buf = open(path,'rb').read()
    info = macho.parse_macho(buf, 0)
    res = set()
    for sseg, sect, off, size in cstr.sections_of(buf, info, 0):
        if sect in secs and size:
            for s in cstr.cstrings(buf, off, size, minlen):
                if cstr.clean(s): res.add(s)
    return res

if __name__ == '__main__':
    A, B = sys.argv[1], sys.argv[2]
    ba, ia, fa = funcs(A); bb, ib, fb = funcs(B)
    print('funcs A=%d B=%d' % (len(fa), len(fb)))
    ha = {vm: hashlib.sha256(v[0]).hexdigest() for vm, v in fa.items()}
    hb = {vm: hashlib.sha256(v[0]).hexdigest() for vm, v in fb.items()}
    # same addresses (same link base) -> compare
    common = set(fa) & set(fb)
    changed = [vm for vm in common if ha[vm] != hb[vm]]
    print('same-vmaddr common=%d changed=%d' % (len(common), len(changed)))
    sa, sb = strings(A), strings(B)
    print('\n--- strings only in 27.2 (A) ---')
    for s in sorted(sb - sa): print('  +', s)
    print('\n--- strings only in 27.0.1 (B) ---')
    for s in sorted(sa - sb): print('  -', s)
    json.dump({'changed': [hex(x) for x in sorted(changed)]}, open(A + '.funcs.json','w'))
