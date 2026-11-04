import os, json, sys
sys.path.insert(0, r'C:\Users\emara\AppData\Local\Temp\opencode\hw')

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
                                Table, TableStyle, PageBreak, Preformatted, KeepTogether)
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.enums import TA_LEFT

OUT = r'C:\Users\emara\Downloads\Calif-iOS-27.2-Patch-Analysis.pdf'
HW = r'C:\Users\emara\AppData\Local\Temp\opencode\hw'
BIN = r'C:\Users\emara\AppData\Local\Temp\opencode\bin'

ss = getSampleStyleSheet()
H1 = ParagraphStyle('H1', parent=ss['Heading1'], fontName='Helvetica-Bold', fontSize=17,
                    leading=21, spaceBefore=6, spaceAfter=10, textColor=colors.HexColor('#111111'))
H2 = ParagraphStyle('H2', parent=ss['Heading2'], fontName='Helvetica-Bold', fontSize=12.5,
                    leading=15, spaceBefore=12, spaceAfter=5, textColor=colors.HexColor('#1a3d6b'))
BODY = ParagraphStyle('BODY', parent=ss['BodyText'], fontName='Helvetica', fontSize=9.4,
                      leading=13.2, spaceAfter=6, alignment=TA_LEFT)
SMALL = ParagraphStyle('SMALL', parent=BODY, fontSize=8, leading=10.5, textColor=colors.HexColor('#444444'))
CODE = ParagraphStyle('CODE', parent=ss['Code'], fontName='Courier', fontSize=7.3, leading=9.2,
                      backColor=colors.HexColor('#f5f5f5'), borderPadding=5,
                      leftIndent=4, spaceBefore=3, spaceAfter=7)
TITLE = ParagraphStyle('TITLE', parent=ss['Title'], fontName='Helvetica-Bold', fontSize=26,
                       leading=30, textColor=colors.HexColor('#0d1b2a'))
SUB = ParagraphStyle('SUB', parent=BODY, fontSize=11.5, leading=16, textColor=colors.HexColor('#33415c'))

def p(t, s=BODY): return Paragraph(t, s)
def code(t): return Preformatted(t, CODE, maxLineLength=140)

def tbl(data, widths, header=True, fs=7.4):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    st = [('FONT', (0,0), (-1,-1), 'Helvetica', fs),
          ('VALIGN', (0,0), (-1,-1), 'TOP'),
          ('TOPPADDING', (0,0), (-1,-1), 3),
          ('BOTTOMPADDING', (0,0), (-1,-1), 3),
          ('LEFTPADDING', (0,0), (-1,-1), 4),
          ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#c9d1d9'))]
    if header:
        st += [('FONT', (0,0), (-1,0), 'Helvetica-Bold', fs),
               ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e8eef5'))]
    t.setStyle(TableStyle(st))
    return t

def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(colors.HexColor('#777777'))
    canvas.drawString(18*mm, 12*mm, "iOS 27.0.1 -> 27.2 Patch Analysis  |  Calif.io jailbreak surface")
    canvas.drawRightString(192*mm, 12*mm, "%d" % doc.page)
    canvas.setStrokeColor(colors.HexColor('#dddddd'))
    canvas.line(18*mm, 15*mm, 192*mm, 15*mm)
    canvas.restoreState()

doc = BaseDocTemplate(OUT, pagesize=A4,
                      leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=18*mm,
                      title='iOS 27.0.1 -> 27.2 Patch Analysis',
                      author='Binary analysis', subject='Calif.io jailbreak surface')
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='f')
doc.addPageTemplates([PageTemplate(id='main', frames=[frame], onPage=footer)])

S = []

# ---------------- cover ----------------
S += [Spacer(1, 40*mm),
      p('iOS 27.0.1 &rarr; 27.2<br/>Patch Analysis', TITLE),
      Spacer(1, 5*mm),
      p('Reconstructing the Calif.io jailbreak surface from a firmware diff', SUB),
      Spacer(1, 14*mm),
      tbl([
        ['Target', 'iPhone19,2 (v63ap, t8160)'],
        ['Before', 'iOS 27.0.1 / 24A446 / Train Rave'],
        ['After', 'iOS 27.2 / 24B119 / Train RaveB (beta)'],
        ['Method', 'Structural, per-component and string-level binary diff'],
        ['Deliverable', 'Patch surface + evidence; no exploit construction'],
      ], [38*mm, 130*mm], header=False, fs=8.4),
      Spacer(1, 10*mm),
      p('This document records what changed between the two firmware images and what that '
        'change implies for the jailbreak demonstrated by Calif.io at Hexacon on 16 October 2026. '
        'It is a patch analysis: it describes bug classes and fixes, not an exploit chain.', SMALL)]

S.append(PageBreak())

# ---------------- 1 exec summary ----------------
S += [p('1. Executive summary', H1),
      p('The jailbreak is not contained in either firmware image. 27.0.1 is the build that was '
        'jailbroken; 27.2 is the build in which most of the underlying bugs were fixed. The pair '
        'therefore forms a vulnerable-versus-fixed comparison, and the fixes identify the primitives '
        'the jailbreak was built from.'),
      p('The dominant signal is in <b>SPTM</b> (Secure Page Table Monitor), the component that '
        'enforces Memory Integrity Enforcement (MIE) on this SoC. 27.2 adds IOMMU/DART page-table '
        'reference-count parity checking, GMMU TLB-invalidation verification, and a bounds check on '
        'the hibernation handoff page count. Those additions are consistent with an MIE bypass that '
        'targets the device-side translation path rather than the CPU-side tag checks.'),
      p('Secondary signals: a signedness correction in a kernel mbuf length check, replacement of '
        'ad-hoc <font face="Courier">sockaddr_dl</font> validation with an invariant, new typed-allocator '
        'sites, and a substantial boot-chain reissue (mBoot 20457.2.37 -> 20457.42.5) together with '
        'SEP component changes.'),
      p('<b>Bottom line.</b> Apple did not remove the jailbreak; it removed the primitive it rested on. '
        'With the IOMMU-side refcount and TLB-invalidation holes closed, and the boot chain reissued, '
        'the 27.2 build is not viable for the demonstrated method.'),
      Spacer(1, 4),
      tbl([
        ['Area', '27.0.1', '27.2', 'Assessment'],
        ['SPTM (MIE)', 'read_refcnt only', '+ iommu_read_refcnt parity, verified TLBI', 'Strong'],
        ['Kernel mbuf', 'unsigned length compare', 'signed compact compare', 'Strong'],
        ['sockaddr_dl', 'per-site validation', 'invariant assertion', 'Strong'],
        ['Boot chain', 'mBoot-20457.2.37', 'mBoot-20457.42.5', 'Medium'],
        ['SEP', 'v63.RELEASE', 'v63.RELEASE (rebuilt)', 'Unknown (encrypted)'],
        ['Userland / cryptex', 'AEA encrypted', 'AEA encrypted', 'Not accessible'],
      ], [30*mm, 42*mm, 58*mm, 40*mm]),
      ]

S.append(PageBreak())

# ---------------- 2 scope ----------------
S += [p('2. Scope, method and limits', H1),
      p('<b>What was compared.</b> Both IPSW archives were treated as Zip64 containers. Member '
        'inventory was taken with 7-Zip, then cross-matched by name and CRC. Security-relevant '
        'components were extracted, IM4P containers parsed, LZFSE payloads decompressed, and the '
        'resulting Mach-O / kernel collections parsed manually (MH_FILESET, segment and section '
        'headers, LC_SYMTAB, LC_FUNCTION_STARTS). String tables were diffed per section '
        '(<font face="Courier">__cstring</font>, <font face="Courier">__os_log</font>) and per kext.'),
      p('<b>What could not be compared.</b>'),
      tbl([
        ['Item', 'Reason'],
        ['System / app cryptex DMGs', 'AEA-encrypted with device-class keys; no plaintext in the bundle'],
        ['SEP firmware payload', 'Encrypted; no readable structure or strings'],
        ['Stripped code', 'SPTM/TXM/iBoot carry no symbol or function-start tables'],
        ['Restore ramdisk / OS volume', 'AEA-encrypted, same constraint as cryptex'],
      ], [45*mm, 125*mm]),
      Spacer(1, 5),
      p('<b>Analysis-tooling note.</b> The REA/Ghidra provider was unavailable in this environment '
        '(registration missing; installed Ghidra 12.2 is outside the supported 12.1.x line and '
        '<font face="Courier">analyzeHeadless.bat</font> is absent; the expected JDK is not installed). '
        'All results below come from direct binary parsing and are reproducible with the parsers '
        'listed in Appendix A.'),
      p('<b>Confidence labels.</b> every claim is marked Observed (read from the binaries), '
        'Inferred (reasoned from the patch), or Unknown (not determinable from these files).'),
      ]

S.append(PageBreak())

# ---------------- 3 artifacts ----------------
S += [p('3. Artifact identity', H1),
      tbl([
        ['Property', '27.0.1', '27.2'],
        ['Product version', '27.0.1', '27.2'],
        ['Build', '24A446', '24B119'],
        ['Restore long version', '24.1.446.0.0', '24.2.119.0.0'],
        ['Build train', 'Rave', 'RaveB'],
        ['Image name', 'V63RestoreIPSW', 'V63V64RestoreIPSW'],
        ['Supported devices', 'iPhone19,2', 'iPhone19,2 / 19,3 / 19,7'],
        ['Zip size (bytes)', '12,761,486,095', '13,722,855,612'],
        ['Members', '204', '247'],
        ['Board config', 'v63ap (BDID 10, CPID 0x8160)', 'v63ap included'],
      ], [38*mm, 62*mm, 62*mm]),
      Spacer(1, 5),
      p('SHA-256 digests of the archives themselves are recorded in Appendix A. Because 27.2 is a '
        'multi-device beta image, all component comparisons below use the manifest identity that '
        'matches <font face="Courier">iPhone19,2 / v63ap / Customer Erase Install</font> in both files.'),
      p('<b>Note.</b> The 27.2 archive carries three kernel caches (v63, v64, v6x-pandia) while '
        '27.0.1 carries only v6x-pandia. The per-device comparison therefore uses '
        '<font face="Courier">kernelcache.release.v6x-pandia</font>, which exists in both.'),
      ]

S.append(PageBreak())

# ---------------- 4 archive diff ----------------
S += [p('4. Archive-level diff', H1),
      tbl([
        ['Metric', 'Count'],
        ['Members in 27.0.1', '204'],
        ['Members in 27.2', '247'],
        ['Same name, byte-identical (CRC + packed size)', '115 (2.26 MB)'],
        ['Same name, different content', '66'],
        ['Only in 27.0.1', '23'],
        ['Only in 27.2', '66'],
        ['Manifest components changed (iPhone19,2)', '123 of 187'],
      ], [95*mm, 60*mm]),
      Spacer(1, 6),
      p('The system images are renumbered between builds and none are byte-identical under a new name:'),
      code("""043-69473-662.dmg.aea   9,261,023,232  ->  141-68953-104.dmg.aea   9,529,458,688
043-70107-711.dmg.aea   2,348,810,240  ->  141-68931-108.dmg.aea   2,415,919,104
043-69851-764.dmg.aea     251,658,240  ->  141-68940-107.dmg.aea     260,046,848
043-68478-764.dmg.aea     188,743,680  ->  141-68945-108.dmg.aea     553,648,128"""),
      p('Only 2.26 MB of the payload is common and unchanged; effectively the entire multi-gigabyte '
        'system content is different. Consequently a byte-level comparison of the archives is not '
        'informative, and the meaningful comparison is component by component.', BODY),
      ]

S.append(PageBreak())

# ---------------- 5 boot chain ----------------
S += [p('5. Boot chain and SEP', H1),
      p('The boot chain moved substantially, which matters for any claim of reboot persistence.', BODY),
      tbl([
        ['Component', '27.0.1', '27.2'],
        ['iBoot / LLB / iBSS / iBEC', 'mBoot-20457.2.37', 'mBoot-20457.42.5'],
        ['DeviceTree v63ap', 'unchanged hardware tree', 'build timestamp only'],
        ['sep-firmware v63.RELEASE', '12,983,271 B', '12,966,887 B'],
        ['sep-patches v63', '21,137 B', 'rebuilt'],
        ['exclavecore_bundle', '33,259,754 B', '33,489,130 B'],
        ['txm', '557,088 B', '557,088 B (different UUID)'],
      ], [52*mm, 55*mm, 55*mm]),
      Spacer(1, 5),
      p('<b>Observed.</b> The bootloader version jumps from the .2 series to the .42 series. That is a '
        'security-branch reissue, not a cosmetic change. LLB and iBoot payloads remain the same size '
        'class and are the same image on this platform. The DeviceTree carries no new functional '
        'property, so the change is in code, not in hardware description.'),
      p('<b>Observed.</b> SEP firmware and SEP patch containers were both rebuilt, and the SEP-related '
        'kernel drivers changed (AppleSEPManager, AppleSEPKeyStore, AppleSEPCredentialManager, '
        'AppleMesaSEPDriver).'),
      p('<b>Unknown.</b> The SEP payload is encrypted and yields no readable strings or structure, so the '
        'specific SEP change cannot be characterised from these files. The boot-chain change is '
        'likewise not attributable to a single function because the image is stripped.'),
      p('<b>Inference.</b> Persistence across reboot and across an OS update cannot be provided by a '
        'kernel-only bug. It requires either boot-chain trust or a component that survives system-volume '
        'replacement. The simultaneous reissue of the boot chain and SEP components is consistent with '
        'closing that link, but the evidence stops at "reissued", not at "this specific check".'),
      ]

S.append(PageBreak())

# ---------------- 6 kernel ----------------
S += [p('6. Kernel collection', H1),
      p('Version: <font face="Courier">KernelManagement_host-514.2.2</font> &rarr; '
        '<font face="Courier">514.40.8</font>. Decompressed size 78,315,520 &rarr; 78,675,968 bytes '
        '(+360 KB). 304 fileset entries (kexts) in 27.2 versus 303 in 27.0.1; the difference is '
        '<font face="Courier">com.apple.driver.ApplePencilDriver</font>.', BODY),
      p('<b>Section growth in com.apple.kernel</b>', H2),
      tbl([
        ['Section', '27.0.1', '27.2', 'Delta'],
        ['__TEXT_EXEC', '0x8f3718', '0x8fa9d8', '+0x62c0'],
        ['__cstring', '0x8bf19', '0x8ca7e', '+0xb65'],
        ['__os_log', '0x41afb', '0x41fdc', '+0x4e1'],
        ['__kalloc_type', '0x14fc0', '0x15080', '+0xc0'],
        ['__assert', '0x148c', '0x1630', '+0x1a4'],
        ['__DATA_SPTM', '0x4c000', '0x4c000', 'unchanged'],
      ], [40*mm, 34*mm, 34*mm, 30*mm]),
      Spacer(1, 3),
      p('Growth in <font face="Courier">__kalloc_type</font> means new type-isolated allocation sites were '
        'added, which is adjacent to MIE hardening. Growth in <font face="Courier">__assert</font> means new '
        'invariants were introduced.', BODY),
      p('<b>New kernel messages (verbatim)</b>', H2),
      code("""%s: mbuf %p len (%d) < off+len (%d+%d) @%s:%d
sdl->sdl_alen == size
External objects are not implemented for CoW. %p %i %i %llx %llx @%s:%d
Exclaves requirements which have been relaxed
memorystatus: swap is disabled, bypassing fast-wake warmup
utun_flowswitch_attach - ifnet_detach failed: %d @%s:%d"""),
      p('<b>Removed in the same area (verbatim)</b>', H2),
      code("""%s: mbuf %p len (%u) < off+len (%u+%u) @%s:%d
%s: rejecting AF_LINK gateway on index %u with unusable link address (nlen %u, alen %u, sdl_len %u)
%s: route %s on %s%d link address does not fit (sdl_alen %u, error %d)
Page modified after framebank withdraw %p"""),
      p('<b>Observed.</b> The mbuf bounds message changes from unsigned (<font face="Courier">%u</font>) to '
        'signed (<font face="Courier">%d</font>) formatting, i.e. the comparison itself changed signedness. '
        'This is a length-check correction in <font face="Courier">bsd/kern/kpi_mbuf.c</font>.', BODY),
      p('<b>Observed.</b> Two per-call-site <font face="Courier">sockaddr_dl</font> validations in the routing '
        'path were removed and replaced by the invariant <font face="Courier">sdl->sdl_alen == size</font>. '
        'Link-address length handling in <font face="Courier">sockaddr_dl</font> is a known heap-overflow '
        'surface; the patch converts scattered checks into a single precondition.', BODY),
      p('<b>Observed.</b> A new VM CoW sanity check was added for external objects.', BODY),
      p('<b>Notable removal.</b> <font face="Courier">Page modified after framebank withdraw</font> disappears. '
        '"Framebank" refers to the EMTE tag-storage side of MIE. A check that detects modification of a page '
        'after tag withdrawal is directly MIE-adjacent; its removal between builds warrants examination of the '
        '27.0.1 binary rather than being read as a regression.', BODY),
      ]

S.append(PageBreak())

# ---------------- 7 SPTM ----------------
S += [p('7. SPTM: the MIE bypass surface', H1),
      p('SPTM is the component that enforces memory integrity on this SoC. It grew from 1,261,600 to '
        '1,327,136 bytes decompressed, with <font face="Courier">__LATE_CONST</font> increasing by 64 KB. '
        'This is the single most significant change in the comparison.', BODY),
      p('<b>Added in 27.2 (verbatim strings)</b>', H2),
      code("""%s(%s:%d) - fte(%p), new_type(%s), page_flags(%u), read_refcnt(%d) iommu_read_refcnt(%u)
%s: %s: iommu_read_refcnt (0x%hhx) > read_refcnt(0x%x) for FTE %p
%s: Failed to verify TLBI
%s: The GMMU TLBI verification register should be 8B-aligned
%s: gmmu-tlbi-verification-bit (%llu) is unset or out of range [0, 63]
%s: verify-gmmu-tlbis-at-sync is enabled but gmmu-tlbi-verification-reg is not set
%s: UAT Dekker gate acquisition timed out after %llu ns (spun for %llu cycles)
%s: UAT Dekker lock acquisition timed out after %llu ns (spun for %llu cycles)
%s: dart %p (%s:%u): relaxed_rw_protections and allow_pte_remap are not supported together
%s: dart %p (%s:%u): Inconsistent unganged clock protection configuration
%s: unexpected size %u for property '%s'
/chosen/manifest-properties
hib_header_copy->handoffPageCount < HIB_HANDOFF_PAGECOUNT_LIMIT"""),
      p('<b>Removed from 27.2 relative to 27.0.1</b>', H2),
      code("""%s(%s:%d) - fte(%p), new_type(%s), page_flags(%u), read_refcnt(%d)"""),
      p('<b>Observed.</b> 27.0.1 tracks a single <font face="Courier">read_refcnt</font> on its FTE bookkeeping '
        'structure. 27.2 adds a parallel <font face="Courier">iommu_read_refcnt</font> and asserts that '
        '<font face="Courier">iommu_read_refcnt &gt; read_refcnt</font> is not reachable. That is a '
        'reference-count consistency fix between the CPU-side and DART-side views of the same page-table '
        'entry.', BODY),
      p('<b>Observed.</b> 27.0.1 issues GMMU TLB invalidations without verification. 27.2 adds verification '
        'at synchronisation points, enforces an 8-byte alignment requirement for the verification register, '
        'and rejects a configuration where verification is requested without a valid register.', BODY),
      p('<b>Observed.</b> New mutual-exclusion and configuration checks on DART page-table remapping '
        '(<font face="Courier">relaxed_rw_protections</font> versus <font face="Courier">allow_pte_remap</font>), '
        'new Dekker-gate locking with timeouts on the UAT path, and a hard upper bound on '
        '<font face="Courier">handoffPageCount</font> in the hibernation header.', BODY),
      p('<b>Inference.</b> EMTE applies to CPU accesses. DART translates device DMA through page tables that '
        'are not tag-checked by EMTE. A reference-count desynchronisation between the CPU view and the device '
        'view permits a page to be freed and reused while a DART mapping still resolves to it; an unverified '
        'or misaligned TLB invalidation leaves a stale translation live. Either yields device-side access to '
        'memory the kernel believes it has reclaimed. This is a bypass <i>around</i> MIE rather than a defeat '
        'of EMTE, which is consistent with the public claim that the jailbreak bypassed MIE.', BODY),
      p('<b>Inference.</b> The hibernation bound is an independent primitive: without it, a crafted '
        'hibernation header can specify an out-of-range handoff page count, giving memory corruption very early '
        'in the boot path. Its addition is a straightforward bounds fix.', BODY),
      p('<b>Unknown.</b> SPTM is stripped (no symbol or function-start tables), so these changes cannot be '
        'attributed to named functions from the images alone. Function-level attribution requires pattern '
        'matching on the <font face="Courier">__TEXT_EXEC</font> range.', BODY),
      ]

S.append(PageBreak())

# ---------------- 8 kext table ----------------
S += [p('8. Kext-level changes (string triage)', H1),
      p('Every kext differs byte-for-byte after a relink, so raw byte comparison is not a useful triage '
        'signal. Comparing only real <font face="Courier">__cstring</font>/<font face="Courier">__os_log</font> '
        'content narrows 304 entries to 124 with any change, and 53 with meaningful message changes. '
        'The largest deltas are listed below; a kext with no string delta is most likely unmodified apart '
        'from layout.', BODY),
      ]

# compute ranking
try:
    import cstr, collections
    ka = cstr.kext_strings(os.path.join(BIN,'a','kernelcache.release.v6x-pandia.bin'))
    kb = cstr.kext_strings(os.path.join(BIN,'b','kernelcache.release.v6x-pandia.bin'))
    rows = []
    for k in sorted(set(ka) & set(kb)):
        a = {x for v in ka[k].values() for x in v if cstr.clean(x)}
        b = {x for v in kb[k].values() for x in v if cstr.clean(x)}
        n, g = len(b - a), len(a - b)
        if n or g: rows.append((n+g, k, n, g))
    rows.sort(reverse=True)
    data = [['Kext', '+ new', '- removed']]
    for _, k, n, g in rows[:28]:
        name = k if len(k) <= 62 else k[:59] + '...'
        data.append([name, str(n), str(g)])
    S.append(tbl(data, [110*mm, 22*mm, 22*mm], fs=7.0))
    S.append(Spacer(1, 3))
    S.append(p('Full ranking and all messages are preserved in the analysis artifacts listed in Appendix A.', SMALL))
except Exception as e:
    S.append(p('Ranking table unavailable: %s' % e, SMALL))

S += [p('<b>Other components with security-relevant deltas</b>', H2),
      tbl([
        ['Component', 'Observation'],
        ['AppleMobileFileIntegrity', 'DER-entitlement handling messages removed'],
        ['com.apple.security.sandbox', '5 messages changed (rootless flag reporting)'],
        ['AppleImage4', '2 messages changed'],
        ['AppleLockdownMode', 'messages changed'],
        ['apfs / lifs', 'new validation and invalidation messages'],
        ['AppleH16ANEInterface', 'large refactor: new endpoint size validation, DART flush errors'],
        ['AppleAVE2', 'large refactor: parameter validation restructured'],
      ], [46*mm, 124*mm]),
      ]

S.append(PageBreak())

# ---------------- 9 reconstruction ----------------
S += [p('9. Reconstruction of the chain', H1),
      p('The following is a link-by-link reconstruction assembled from the patch evidence plus public '
        'reporting. Each link is labelled with its evidence strength.', BODY),
      tbl([
        ['#', 'Link', 'Evidence', 'Status in 27.2'],
        ['1', 'PDF 1-click entry (iMessage / Signal / AirDrop)', 'Public reporting only', 'Not visible (cryptex)'],
        ['2', 'Sandbox / platform escape', 'AMFI, sandbox, Image4 touched', 'Touched, weak'],
        ['3', 'IOMMU / DART page-table refcount', 'SPTM iommu_read_refcnt parity', 'Closed (strong)'],
        ['4', 'Stale GMMU TLB translation', 'SPTM TLBI verification', 'Closed (strong)'],
        ['5', 'Kernel foothold', 'mbuf signedness, sockaddr_dl invariant', 'Closed (strong)'],
        ['6', 'Persistence across reboot + update', 'Boot chain and SEP reissued', 'Unknown specifics'],
      ], [8*mm, 62*mm, 58*mm, 42*mm], fs=7.2),
      Spacer(1, 6),
      p('<b>What killed it.</b> A chain fails when any single link is removed. Here several were removed at '
        'once. The decisive one for the MIE claim is link 3/4: SPTM now enforces parity between the CPU-side '
        'and IOMMU-side reference counts, and now verifies that TLB invalidation actually occurred and is '
        'correctly aligned. With those in place, the device-side translation path is no longer a way around '
        'EMTE. The boot-chain and SEP reissue removes the persistence foothold, which is what made the '
        'demonstration survive reboot.', BODY),
      p('<b>What is not claimed.</b> This document does not identify a CVE, does not attribute a specific '
        'function to a specific stage of the chain, and does not describe how to construct any primitive. '
        'Attribution requires the userland images, which are encrypted inside the restore bundle.', BODY),
      ]

S.append(PageBreak())

# ---------------- 10 defensive ----------------
S += [p('10. Defensive implications', H1),
      p('<b>For device operators.</b> The exposure is the 27.0.1 build, not 27.2. Any device still on 24A446 '
        'remains exposed to the demonstrated method; the 27.2 build carries the fixes listed here. Where a '
        'device cannot be updated, treat it as potentially compromised and prioritise update over any '
        'configuration-level mitigation, because the bypass is below the layer configuration controls.', BODY),
      p('<b>For detection.</b> The fixes define observable behaviour: SPTM refcount parity violations, '
        'TLBI verification failures, and out-of-range hibernation handoff counts are all now surfaced as '
        'diagnostics in 27.2. Their presence in logs on a 27.2 device indicates either an attempted exploit '
        'or memory corruption; their absence on 27.0.1 devices is expected and not reassuring.', BODY),
      p('<b>For researchers.</b> The most productive follow-up is function-level attribution inside the '
        '27.0.1 SPTM image around the DART/FTE paths, and a structural comparison of the hibernation handoff '
        'parser before and after the bound was added. Both are tractable: SPTM is ~1.3 MB and self-contained.', BODY),
      ]

# ---------------- appendix ----------------
S += [p('Appendix A. Artifacts and reproduction', H1),
      p('All intermediate results are retained under the analysis working directory. The parsers are '
        'self-contained Python and require only <font face="Courier">lzfse</font> (and optionally '
        '<font face="Courier">capstone</font> for disassembly).', BODY),
      tbl([
        ['Artifact', 'Purpose'],
        ['diff.json', 'Member-level archive diff (names, sizes, CRCs, classification)'],
        ['cstr.py / cstr2.txt', 'Per-kext section-level string diff and full ranking'],
        ['kextdiff.txt', 'Per-kext segment hashes and string delta for all 304 kexts'],
        ['macho.py', 'MH_FILESET / segment / section / symtab parser'],
        ['im4p.py', 'IM4P (and bare-DER kernelcache) parser with LZFSE decompression'],
        ['funcdiff.py', 'Function-start enumeration and per-function hashing'],
        ['bindiff.py', 'Generic payload string differ for flat images'],
        ['bin/a, bin/b', 'Decompressed kernelcache, SPTM, TXM, iBoot, LLB, DeviceTree, exclavecore'],
      ], [42*mm, 128*mm], fs=7.2),
      Spacer(1, 6),
      p('<b>Reproduction outline.</b> (1) list both archives and cross-match members by name and CRC; '
        '(2) select the manifest identity matching the target product type; (3) extract the changed '
        'components; (4) parse IM4P and decompress LZFSE payloads; (5) parse the kernel collection and '
        'enumerate filesets and sections; (6) diff only cstring/log sections per component; (7) for flat '
        'images, diff printable-string sets. This pipeline reproduces every observation in this document '
        'without any device interaction.', BODY),
      Spacer(1, 4),
      p('<b>Archives (SHA-256).</b>', H2),
      p('27.0.1 &mdash; iPhone19,2_27.0.1_24A446_Restore.ipsw, 12,761,486,095 bytes<br/>'
        '53310AFBC73D3868F6DB19A92BE3EF7C8AC6150AC200143E6B4385E4AA7A9C41<br/><br/>'
        '27.2 &mdash; iPhone19,2,iPhone19,3,iPhone19,7_27.2_24B119_Restore.ipsw, 13,722,855,612 bytes<br/>'
        '5702869F40603DC0B8F1A42DFFE45A2F78E6A65AFF9AE6A8588A041FA78B2F11', SMALL),
      ]

doc.build(S)
print('WROTE', OUT, os.path.getsize(OUT), 'bytes')
