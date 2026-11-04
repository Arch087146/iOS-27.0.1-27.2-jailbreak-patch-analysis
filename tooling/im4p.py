import struct, sys, os, lzfse

def der_items(buf, off, end, out):
    while off < end:
        tag = buf[off]
        off += 1
        l = buf[off]; off += 1
        if l & 0x80:
            n = l & 0x7f
            l = int.from_bytes(buf[off:off+n], 'big'); off += n
        if tag == 0x30:
            der_items(buf, off, off+l, out)
        else:
            out.append((tag, off, l))
        off += l
    return out

def parse_im4p(path):
    buf = open(path,'rb').read()
    if buf[:4] == b'IM4P':
        start = 8
    elif buf[0] == 0x30:
        start = 0   # kemelcache: bare DER, no IM4P magic
    else:
        raise ValueError('not im4p: %r' % buf[:4])
    items = []
    der_items(buf, start, len(buf), items)
    strs = [buf[o:o+l] for t,o,l in items if t in (0x0c, 0x16)]
    octs = [(o,l) for t,o,l in items if t == 0x04]
    return buf, strs, octs

def payload_of(path):
    head = open(path,'rb').read(4)
    if head[:4] != b'IM4P' and head[0] != 0x30:
        return open(path,'rb').read(), ('raw', head)
    buf, strs, octs = parse_im4p(path)
    # first OCTET STRING is the payload
    o,l = octs[0]
    p = buf[o:o+l]
    tag = p[:4]
    if tag in (b'bvx2', b'bvx-', b'bvxn', b'bvx$'):
        d = lzfse.decompress(p)
        return d, ('lzfse', tag)
    return p, tag

if __name__ == '__main__':
    for p in sys.argv[1:]:
        buf, strs, octs = parse_im4p(p)
        d, tag = payload_of(p)
        print(os.path.basename(p), '| types:', [s.decode('latin1') for s in strs][:3], '| payload', len(d), tag)
        out = p + '.bin'
        open(out,'wb').write(d)
