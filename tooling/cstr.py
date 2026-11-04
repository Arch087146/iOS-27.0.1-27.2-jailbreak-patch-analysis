import struct, sys, os, json, collections
import macho

def sections_of(buf, info, base=0):
    """return list of (segname, sectname, fileoff, size) from LC_SEGMENT_64 section headers"""
    out = []
    ncmds = info['ncmds']
    off = base + 32  # 64-bit header
    for _ in range(ncmds):
        cmd = struct.unpack_from('<I', buf, off)[0]
        cmdsize = struct.unpack_from('<I', buf, off+4)[0]
        if cmd == macho.LC_SEGMENT_64:
            segname = buf[off+8:off+24].split(b'\0')[0].decode('latin1')
            nsects = struct.unpack_from('<I', buf, off+64)[0]
            so = off + 72
            for i in range(nsects):
                sectname = buf[so:so+16].split(b'\0')[0].decode('latin1')
                sseg = buf[so+16:so+32].split(b'\0')[0].decode('latin1')
                addr, size, offset = struct.unpack_from('<QQI', buf, so+32)
                out.append((sseg, sectname, offset, size))
                so += 80
        off += cmdsize
        if cmdsize == 0: break
    return out

WANT = {'__cstring','__os_log','__ustring'}

def cstrings(buf, off, size, minlen=6):
    s = buf[off:off+size]
    res = []
    cur = bytearray()
    for ch in s:
        if 32 <= ch < 127:
            cur.append(ch)
        else:
            if len(cur) >= minlen: res.append(bytes(cur).decode('latin1'))
            cur = bytearray()
    if len(cur) >= minlen: res.append(bytes(cur).decode('latin1'))
    return res

def clean(s):
    if len(s) < 8: return False
    if s.startswith('/Library/Caches/'): return False
    if s.startswith('com.apple.') and len(s) < 30: return False
    letters = sum(c.isalpha() for c in s)
    if letters < 5: return False
    good = sum(1 for c in s if c.isalnum() or c in ' _%.:/()[],<>=@#!?+-*&"\'')
    if good / len(s) < 0.9: return False
    # require at least two words or a format specifier
    return (' ' in s) or ('%' in s) or (':' in s) or ('/' in s)

def kext_strings(path):
    b = open(path,'rb').read()
    root = macho.parse_macho(b, 0)
    out = {}
    for eid, fo, va in root['filesets']:
        ci = macho.parse_macho(b, fo)
        if not ci: continue
        secs = {}
        for sseg, sect, off, size in sections_of(b, ci, fo):
            if sect in WANT and size > 0:
                secs.setdefault(sect, []).extend(cstrings(b, off, size))
        out[eid] = secs
    return out

if __name__ == '__main__':
    ka = kext_strings(sys.argv[1]); kb = kext_strings(sys.argv[2])
    rows = []
    for k in sorted(set(ka) & set(kb)):
        a = collections.Counter(x for v in ka[k].values() for x in v if clean(x))
        bb = collections.Counter(x for v in kb[k].values() for x in v if clean(x))
        new = set(bb) - set(a); gone = set(a) - set(bb)
        if new or gone:
            rows.append((len(new)+len(gone), k, new, gone))
    rows.sort(reverse=True)
    print('kexts with cstring changes:', len(rows))
    lim = int(sys.argv[3]) if len(sys.argv) > 3 else 25
    for n, k, new, gone in rows[:lim]:
        print(f'\n{"="*70}\n{k}  (+{len(new)} / -{len(gone)})')
        for s in sorted(new)[:60]: print('  +', s)
        for s in sorted(gone)[:20]: print('  -', s)
    print('\n\n### RANKING (all) ###')
    for n, k, new, gone in rows:
        print(f'{n:5d}  +{len(new):4d} -{len(gone):4d}  {k}')
