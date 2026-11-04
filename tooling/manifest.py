import plistlib, os, json, hashlib

base = r"C:\Users\emara\AppData\Local\Temp\opencode\ipsw"
A = os.path.join(base, 'a'); B = os.path.join(base, 'b')

def load(p):
    with open(p,'rb') as f: return plistlib.load(f)

ma = load(os.path.join(A,'BuildManifest.plist'))
mb = load(os.path.join(B,'BuildManifest.plist'))

def ident_key(i):
    idn = i.get('Identity', {})
    return '|'.join(str(idn.get(k,'')) for k in ('ProductType','ApBoardID','ApChipID','ApSecurityDomain','Variant'))

def comps(m):
    out = {}
    for i in m.get('BuildIdentities', []):
        k = ident_key(i)
        d = {}
        for name, c in i.get('Manifest', {}).items():
            info = c.get('Info', {})
            d[name] = (c.get('Digest'), info.get('Path'), info.get('IsFTAB'), info.get('Img4PayloadDigest'))
        out[k] = d
    return out

ca, cb = comps(ma), comps(mb)
print("A identities:")
for k in ca: print("  ", k)
print("B identities:")
for k in cb: print("  ", k)

# compare matching identities
common = sorted(set(ca) & set(cb))
print("\nmatching identity count:", len(common))
for k in common:
    a, b = ca[k], cb[k]
    print("\n### IDENTITY:", k)
    for name in sorted(set(a) | set(b)):
        if name not in a: print(f"  + {name}  ({b[name][1]})"); continue
        if name not in b: print(f"  - {name}  ({a[name][1]})"); continue
        if a[name][0] != b[name][0]:
            print(f"  ~ {name}\n      pathA={a[name][1]}\n      pathB={b[name][1]}\n      dgstA={a[name][0]}\n      dgstB={b[name][0]}")
