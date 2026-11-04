import struct, hashlib, sys, os, json
import macho

WHITELIST = {'__TEXT','__TEXT_EXEC','__DATA','__DATA_CONST','__DATA_SPTM','__BOOTDATA',
             '__LASTDATA_CONST','__KLD','__KLDDATA','__TEXT_BOOT_EXEC'}

def kexts(path):
    b = open(path,'rb').read()
    root = macho.parse_macho(b, 0)
    out = {}
    for eid, fo, va in root['filesets']:
        ci = macho.parse_macho(b, fo)
        if not ci: continue
        h = hashlib.sha256()
        segs = []
        for name, vm, vmsz, foff, fsz in ci['segs']:
            if name in WHITELIST and fsz > 0:
                h.update(name.encode()); h.update(b[foff:foff+fsz])
                segs.append((name, foff, fsz))
        out[eid] = {'off': fo, 'hash': h.hexdigest(), 'segs': segs,
                    'srcver': ci.get('srcver'), 'uuid': ci['uuid'], 'info': ci}
    return b, out

def strings_of(b, segs, minlen=4):
    res = set()
    for name, foff, fsz in segs:
        s = b[foff:foff+fsz]
        cur = bytearray()
        for ch in s:
            if 32 <= ch < 127:
                cur.append(ch)
            else:
                if len(cur) >= minlen: res.add(bytes(cur).decode('latin1'))
                cur = bytearray()
        if len(cur) >= minlen: res.add(bytes(cur).decode('latin1'))
    return res

if __name__ == '__main__':
    A = sys.argv[1]; B = sys.argv[2]
    ba, ka = kexts(A); bb, kb = kexts(B)
    print('kext counts: A=%d B=%d' % (len(ka), len(kb)))
    onlyA = sorted(set(ka)-set(kb)); onlyB = sorted(set(kb)-set(ka))
    changed = [k for k in sorted(set(ka)&set(kb)) if ka[k]['hash'] != kb[k]['hash']]
    print('only in A:', len(onlyA)); [print('   -', k) for k in onlyA]
    print('only in B:', len(onlyB)); [print('   +', k) for k in onlyB]
    print('changed:', len(changed))
    json.dump(changed, open('changed_kexts.json','w'), indent=0)
    for k in changed:
        sa = strings_of(ba, ka[k]['segs']); sb = strings_of(bb, kb[k]['segs'])
        new = sorted(sb-sa); gone = sorted(sa-sb)
        print(f'\n### {k}  ({len(ka[k]["segs"])} segs)  new_str={len(new)} gone_str={len(gone)}')
        for s in new[:40]: print('   +', s[:160])
        for s in gone[:10]: print('   -', s[:160])
