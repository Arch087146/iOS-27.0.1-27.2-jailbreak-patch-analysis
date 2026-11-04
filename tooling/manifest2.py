import plistlib, os

base = r"C:\Users\emara\AppData\Local\Temp\opencode\ipsw"
A = os.path.join(base,'a'); B = os.path.join(base,'b')
def load(p):
    with open(p,'rb') as f: return plistlib.load(f)
ma = load(os.path.join(A,'BuildManifest.plist')); mb = load(os.path.join(B,'BuildManifest.plist'))

def pick(m, pt):
    for i in m['BuildIdentities']:
        if i.get('Ap,ProductType')==pt: return i
    return None
a = pick(ma,'iPhone19,2'); b = pick(mb,'iPhone19,2')
print("A identity:", a['Info']['DeviceClass'], a['Info']['Variant'], a['Info']['BuildNumber'])
print("B identity:", b['Info']['DeviceClass'], b['Info']['Variant'], b['Info']['BuildNumber'])

fa = {k:(v.get('Digest'), v.get('Info',{}).get('Path'), v.get('Info',{}).get('IsFTAB')) for k,v in a['Manifest'].items()}
fb = {k:(v.get('Digest'), v.get('Info',{}).get('Path'), v.get('Info',{}).get('IsFTAB')) for k,v in b['Manifest'].items()}

same=diff=0
print("\n=== COMPONENT DIGEST CHANGES (iPhone19,2) ===")
for k in sorted(set(fa)|set(fb)):
    if k not in fa: print(f"+ {k}  {fb[k][1]}"); continue
    if k not in fb: print(f"- {k}  {fa[k][1]}"); continue
    if fa[k][0]!=fb[k][0]:
        diff+=1
        print(f"~ {k:<42} {fa[k][1]}")
    else: same+=1
print(f"\nsame={same} changed={diff}")

print("\n=== INFO / VARIANT DIFFS ===")
ia, ib = a['Info'], b['Info']
for k in sorted(set(ia)|set(ib)):
    if ia.get(k)!=ib.get(k):
        print(f"~ {k}:\n    A={ia.get(k)}\n    B={ib.get(k)}")

print("\n=== IDENTITY FIELD DIFFS ===")
for k in sorted(set(a)|set(b)):
    if k in ('Manifest','Info'): continue
    if a.get(k)!=b.get(k): print(f"~ {k}: A={a.get(k)}  B={b.get(k)}")
