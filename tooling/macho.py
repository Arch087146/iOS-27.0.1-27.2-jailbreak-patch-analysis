import struct, os, sys, subprocess, json

MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca
MH_FILESET = 0xc

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FILESET_ENTRY = 0x35
LC_UUID = 0x1b
LC_BUILD_VERSION = 0x32
LC_SOURCE_VERSION = 0x2A

def u32(b,o): return struct.unpack_from('<I', b, o)[0]
def u64(b,o): return struct.unpack_from('<Q', b, o)[0]

def slices(buf):
    m = u32(buf,0)
    if m in (FAT_MAGIC,):
        n = struct.unpack_from('>I', buf, 4)[0]
        out=[]
        for i in range(n):
            off = 8 + i*20
            cputype, cpusub, foff, fsize, align = struct.unpack_from('>IIIII', buf, off)
            out.append((cputype, foff, fsize))
        return out
    return [(None, 0, len(buf))]

def parse_macho(buf, base=0):
    magic = u32(buf, base)
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        return None
    is64 = magic == MH_MAGIC_64
    hdr = 32 if is64 else 28
    filetype = u32(buf, base+12)
    ncmds = u32(buf, base+16)
    off = base + hdr
    info = {'filetype': filetype, 'ncmds': ncmds, 'uuid': None, 'filesets': [], 'symtab': None,
            'segs': [], 'entry_id': None, 'srcver': None, 'size': 0}
    for _ in range(ncmds):
        cmd = u32(buf, off); cmdsize = u32(buf, off+4)
        if cmd == LC_UUID:
            info['uuid'] = buf[off+8:off+24].hex()
        elif cmd == LC_SEGMENT_64:
            name = buf[off+8:off+24].split(b'\x00')[0].decode('latin1')
            vmaddr = u64(buf, off+24); vmsize = u64(buf, off+32)
            fileoff = u64(buf, off+40); filesize = u64(buf, off+48)
            info['segs'].append((name, vmaddr, vmsize, fileoff, filesize))
            info['size'] = max(info['size'], fileoff+filesize)
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', buf, off+8)
            info['symtab'] = (symoff, nsyms, stroff, strsize)
        elif cmd == (LC_FILESET_ENTRY | 0x80000000):
            vmaddr = u64(buf, off+8); fileoff = u64(buf, off+16)
            idoff = u32(buf, off+24)
            s = off + idoff
            e = buf.find(b'\x00', s, s+256)
            entry_id = buf[s:e].decode('latin1') if e > s else ''
            info['filesets'].append((entry_id, fileoff, vmaddr))
        elif cmd == LC_SOURCE_VERSION:
            info['srcver'] = u64(buf, off+8)
        off += cmdsize
        if cmdsize == 0: break
    return info

def symbols(buf, info):
    if not info['symtab']: return []
    symoff, nsyms, stroff, strsize = info['symtab']
    out = []
    for i in range(nsyms):
        o = symoff + i*16
        if o+16 > len(buf): break
        n_strx = u32(buf, o); n_type = buf[o+4]; n_sect = buf[o+5]
        n_desc = struct.unpack_from('<H', buf, o+6)[0]
        n_value = u64(buf, o+8)
        s = stroff + n_strx
        e = buf.find(b'\x00', s)
        name = buf[s:e].decode('latin1') if e > s else ''
        out.append((name, n_type, n_sect, n_value))
    return out

def walk(buf, base=0, prefix=''):
    info = parse_macho(buf, base)
    if not info: return []
    out = [(prefix, info)]
    for entry_id, fileoff, vmaddr in info['filesets']:
        out += walk(buf, base+fileoff, entry_id)
    return out

if __name__ == '__main__':
    for p in sys.argv[1:]:
        buf = open(p,'rb').read()
        print('='*80)
        print(os.path.basename(p), len(buf))
        for sl in slices(buf):
            print(' slice cputype=%s off=0x%x size=0x%x' % (sl[0], sl[1], sl[2]))
        for pre, info in walk(buf):
            nsym = info['symtab'][1] if info['symtab'] else 0
            print(f"  [{pre or 'ROOT'}] filetype={info['filetype']} size=0x{info['size']:x} syms={nsym} filesets={len(info['filesets'])} uuid={info['uuid']}")
