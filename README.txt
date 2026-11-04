iOS 27.0.1 -> 27.2 PATCH ANALYSIS
=================================
iPhone19,2 (v63ap, t8160) -- vulnerable vs fixed firmware comparison

This folder contains a binary patch analysis of two public IPSW images and
the tooling used to produce it. It documents what Apple changed between the
build that was jailbroken and the build that fixed it.

It is analysis. It contains no exploit code and no decryption keys.


FOLDER LAYOUT
-------------

Calif-iOS-27.2-Patch-Analysis.pdf
    The 12-page report. Start here.

archive-diff/
    diff.json              member-level IPSW diff (names, sizes, CRCs,
                           classification: identical / changed / only-in-A/B)
    ipsw_272.txt           raw 7z listing, 27.2
    ipsw_2701.txt          raw 7z listing, 27.0.1
    ipsw_272.u8.txt        same, re-encoded UTF-8 (PowerShell wrote UTF-16)
    ipsw_2701.u8.txt
    cmp.js                 archive comparison script

tooling/
    macho.py               Mach-O / MH_FILESET / segment / section / symtab parser
    im4p.py                IM4P + bare-DER parser, LZFSE decompression
    cstr.py                section-level __cstring / __os_log extractor
    funcdiff.py            function-start enumeration + per-function string diff
    bindiff.py             flat-image printable-string differ
    kextdiff.py            per-kext diff driver
    manifest.py            BuildManifest comparison
    manifest2.py           BuildManifest per-ProductType component digest diff
    plistcmp.py            generic plist differ
    mkpdf.py               generates the PDF report

results/
    cstr2.txt              ranked per-kext string diff -- the clean signal
                           (53 kexts with meaningful changes out of 304)
    cstr_kernel.txt        kernel section string diff
    kextdiff.txt           full 304-kext dump (hashes + string deltas)
    changed_kexts.json     machine-readable changed-kext list

firmware/
    27.2-fixed/            iOS 27.2 (24B119) decompressed artifacts
    27.0.1-jailbroken/     iOS 27.0.1 (24A446) decompressed artifacts

    Each contains: kernelcache.release.v6x-pandia (.im4p and .bin),
    sptm.t8160.release.im4p (.bin), txm.iphoneos.release (.im4p and .bin),
    iBoot / iBEC / iBSS / LLB v63.RELEASE (.im4p and .bin),
    DeviceTree.v63ap.im4p, sep-firmware.v63.RELEASE.im4p,
    exclavecore_bundle.t8160.RELEASE.im4p

    27.2-fixed/ also has kernelcache.release.v63 (27.0.1 does not ship it).

manifests/
    27.2/  and  27.0.1/
    BuildManifest.plist, Restore.plist, RestoreVersion.plist,
    SystemVersion.plist


SOURCE IMAGES
-------------

(not included here -- too large)

iPhone19,2_27.0.1_24A446_Restore.ipsw
    12,761,486,095 bytes
    SHA-256  53310AFBC73D3868F6DB19A92BE3EF7C8AC6150AC200143E6B4385E4AA7A9C41

iPhone19,2,iPhone19,3,iPhone19,7_27.2_24B119_Restore.ipsw
    13,722,855,612 bytes
    SHA-256  5702869F40603DC0B8F1A42DFFE45A2F78E6A65AFF9AE6A8588A041FA78B2F11


KEY NUMBERS
-----------

Build trains:      27.0.1 = Rave / V63RestoreIPSW
                   27.2   = RaveB / V63V64RestoreIPSW
Kernel version:    KernelManagement_host-514.2.2  ->  514.40.8
Bootloader:        mBoot-20457.2.37  ->  mBoot-20457.42.5
Kext count:        303  ->  304  (+ com.apple.driver.ApplePencilDriver)
SPTM payload:      1,261,600  ->  1,327,136 bytes
Archive members:   204  ->  247
Identical members: 115 (2.26 MB of 12.7 GB)
Changed components (iPhone19,2 manifest): 123 of 187

Primary finding: the MIE bypass surface is SPTM. 27.2 adds IOMMU/DART
page-table reference-count parity checking (iommu_read_refcnt vs
read_refcnt), GMMU TLB-invalidation verification, and a hibernation handoff
page-count bound. Detail is in section 7 of the PDF.


ANALYSIS LIMITS
---------------

- System/app cryptex DMGs are AEA-encrypted; no plaintext in the bundle.
  This is where the userland entry point (PDF / messaging RCE) lives.
- SEP firmware payload is encrypted; no readable structure or strings.
- SPTM, TXM and iBoot are stripped: no LC_SYMTAB, and SPTM has no
  LC_FUNCTION_STARTS. Function-level attribution is not possible from the
  images alone.
- Every kext differs byte-for-byte after relink, so raw byte comparison is
  not a useful signal. String-level triage was used instead.


REQUIREMENTS FOR THE TOOLING
----------------------------

Python 3 with:
    lzfse        (decompression; pip install lzfse)
    capstone     (optional, for disassembly)

Reproduce the report:
    python tooling\mkpdf.py
    (edit the BIN / path constants at the top to point at firmware\...)
