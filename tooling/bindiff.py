import sys, re, os
sys.path.insert(0, r'C:\Users\emara\AppData\Local\Temp\opencode\hw')
import im4p, cstr

def payload(path):
    d, tag = im4p.payload_of(path)
    return d

def strs(buf, minlen=6):
    out = set()
    cur = bytearray()
    for ch in buf:
        if 32 <= ch < 127:
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                s = bytes(cur).decode('latin1')
                if cstr.clean(s) and not s.startswith('/Library/Caches/'):
                    out.add(s)
            cur = bytearray()
    if len(cur) >= minlen:
        s = bytes(cur).decode('latin1')
        if cstr.clean(s): out.add(s)
    return out

if __name__ == '__main__':
    A, B = sys.argv[1], sys.argv[2]
    pa, pb = payload(A), payload(B)
    print('%s: %d bytes' % (os.path.basename(A), len(pa)))
    print('%s: %d bytes' % (os.path.basename(B), len(pb)))
    sa, sb = strs(pa), strs(pb)
    print('\n=== ONLY IN %s (%d) ===' % (os.path.basename(A), len(sa-sb)))
    for s in sorted(sa-sb):
        if 'Apple' in s or 'error' in s.lower() or 'fail' in s.lower() or 'panic' in s.lower() or 'invalid' in s.lower() or 'denied' in s.lower():
            print('  +', s)
    print('\n--- all added (%d) ---' % len(sa-sb))
    for s in sorted(sa-sb)[:120]: print('  +', s)
    print('\n=== ONLY IN %s (%d) ===' % (os.path.basename(B), len(sb-sa)))
    for s in sorted(sb-sa):
        if 'error' in s.lower() or 'fail' in s.lower() or 'panic' in s.lower() or 'invalid' in s.lower() or 'denied' in s.lower():
            print('  -', s)
