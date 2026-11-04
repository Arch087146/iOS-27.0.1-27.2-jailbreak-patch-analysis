import plistlib, json, sys, os

base = r"C:\Users\emara\AppData\Local\Temp\opencode\ipsw"

def load(p):
    with open(p, 'rb') as f:
        return plistlib.load(f)

A = os.path.join(base, 'a'); B = os.path.join(base, 'b')

for name in ['SystemVersion.plist', 'RestoreVersion.plist', 'Restore.plist']:
    a = load(os.path.join(A, name)); b = load(os.path.join(B, name))
    print('='*70); print(name)
    ka, kb = set(a), set(b)
    for k in sorted(ka & kb):
        if a[k] != b[k]:
            print(f'  ~ {k}:\n      A={a[k]}\n      B={b[k]}')
    for k in sorted(ka - kb):
        print(f'  - only A: {k} = {a[k]}')
    for k in sorted(kb - ka):
        print(f'  + only B: {k} = {b[k]}')

ma = load(os.path.join(A, 'BuildManifest.plist'))
mb = load(os.path.join(B, 'BuildManifest.plist'))

print('='*70)
print('BuildManifest top keys:', sorted(ma.keys()))
print('A ProductVersion:', ma.get('ProductVersion'), 'Build:', ma.get('ProductBuildVersion'))
print('B ProductVersion:', mb.get('ProductVersion'), 'Build:', mb.get('ProductBuildVersion'))
print('A SupportedProductTypes:', ma.get('SupportedProductTypes'))
print('B SupportedProductTypes:', mb.get('SupportedProductTypes'))
print('A ProductType:', ma.get('ProductType'), 'B ProductType:', mb.get('ProductType'))
print('A BuildIdentities count:', len(ma.get('BuildIdentities', [])), 'B:', len(mb.get('BuildIdentities', [])))

# per identity compare
ida = {i['Identity']['ProductType'] + '|' + i['Identity'].get('ApBoardID','?') + '|' + i['Identity'].get('ApChipID','?'): i for i in ma.get('BuildIdentities', [])}
idb = {i['Identity']['ProductType'] + '|' + i['Identity'].get('ApBoardID','?') + '|' + i['Identity'].get('ApChipID','?'): i for i in mb.get('BuildIdentities', [])}
print('A identity keys:', sorted(ida)[:20])
print('B identity keys:', sorted(idb)[:20])
