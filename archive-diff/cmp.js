const fs = require('fs');

function parse(file) {
  const txt = fs.readFileSync(file, 'utf8');
  const lines = txt.split(/\r?\n/);
  const entries = [];
  let cur = null;
  let inList = false;
  let meta = {};
  for (const ln of lines) {
    if (ln.startsWith('----------')) { inList = true; continue; }
    if (!inList) {
      const m = ln.match(/^(Physical Size|Type|64-bit|Characteristics) = (.*)$/);
      if (m) meta[m[1]] = m[2];
      continue;
    }
    if (ln === '') {
      if (cur && cur.Path !== undefined) { entries.push(cur); cur = null; }
      continue;
    }
    const i = ln.indexOf(' = ');
    if (i < 0) continue;
    const k = ln.slice(0, i), v = ln.slice(i + 3);
    if (k === 'Path') { if (cur) entries.push(cur); cur = {}; }
    if (!cur) continue;
    cur[k] = v;
  }
  if (cur && cur.Path !== undefined) entries.push(cur);
  return { meta, entries };
}

const A = parse(process.argv[2]); // 27.2
const B = parse(process.argv[3]); // 27.0.1

const norm = p => p.replace(/\\/g, '/');
const mapA = new Map(), mapB = new Map();
for (const e of A.entries) mapA.set(norm(e.Path), e);
for (const e of B.entries) mapB.set(norm(e.Path), e);

const allKeys = new Set([...mapA.keys(), ...mapB.keys()]);
const rows = { onlyA: [], onlyB: [], same: [], changed: [] };

for (const k of allKeys) {
  const a = mapA.get(k), b = mapB.get(k);
  if (a && !b) rows.onlyA.push(a);
  else if (!a && b) rows.onlyB.push(b);
  else {
    const sameContent = a.CRC === b.CRC && a.Size === b.Size;
    const sameRaw = sameContent && a['Packed Size'] === b['Packed Size'] && a.Method === b.Method;
    if (sameContent) rows.same.push({ a, b, sameRaw });
    else rows.changed.push({ a, b });
  }
}

const out = {
  metaA: A.meta, metaB: B.meta,
  counts: {
    entriesA: A.entries.length, entriesB: B.entries.length,
    onlyIn27_2: rows.onlyA.length, onlyIn27_0_1: rows.onlyB.length,
    identicalContent: rows.same.length, changed: rows.changed.length,
    identicalContentAndRawBytes: rows.same.filter(r => r.sameRaw).length
  },
  onlyIn27_2: rows.onlyA.map(e => ({ path: e.Path, size: +e.Size, crc: e.CRC })),
  onlyIn27_0_1: rows.onlyB.map(e => ({ path: e.Path, size: +e.Size, crc: e.CRC })),
  changed: rows.changed.map(({ a, b }) => ({
    path: a.Path,
    size_27_2: +a.Size, size_27_0_1: +b.Size,
    packed_27_2: +a['Packed Size'], packed_27_0_1: +b['Packed Size'],
    crc_27_2: a.CRC, crc_27_0_1: b.CRC,
    method_27_2: a.Method, method_27_0_1: b.Method
  })),
  identicalButRecompressed: rows.same.filter(r => !r.sameRaw).map(r => r.a.Path),
  sameList: rows.same.map(r => ({ path: r.a.Path, size: +r.a.Size }))
};

fs.writeFileSync(process.argv[4], JSON.stringify(out, null, 1));
console.log(JSON.stringify(out.counts, null, 1));
