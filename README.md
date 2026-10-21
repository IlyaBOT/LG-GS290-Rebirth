# LG GS290 Rebirth

Offline reverse engineering of the **LG GS290 Cookie Fresh** (Infineon S-GOLD3 / ARM926EJ-S): firmware formats, J2ME/AROMA VM, Flash/SWF, Obigo/browser, and potential routes to safe execution of owner-controlled ARM code.

**Not a flashing project. Do not flash binaries from this repository.** The owner's handset currently runs **GS290AT_V10k CIS**. The available factory image is **V10C**, downloaded under a SEA label; an internal string indicates `GS290AT-00-V10c-AME-XXX-AUG-09-2010+0`. These are **different firmware versions**, and no V10k binary comparison has been done. A previously downloaded `V10D_00.kdz` belonged to **GU297/Qualcomm** and must not be confused with GS290.

## State of analysis

Codex decoded the legacy KDZ → CAB → WDB (RC4/MD5) → Infineon FLS/FLB layers, then recovered two ARM main segments and a FAT16 filesystem. The RC4 key material comes from the **size of Inf_WebDnld.dll (163840)**, not the WDB's size. The original V10C KDZ SHA-256 is:

`b772aeb6a4fb9325e3fcc497363c675b8286201dbc85f1832bd86187d87f754f`

New static audit: **[Java, Flash, Obigo/browser findings](analysis/FINDINGS_V10C_SEA.md)**. There is a credible memory-safety candidate in Java's native JAR/DEFLATE decoder and an unencrypted HTTP → unescaped persisted string → `eval` path in the bundled Weather widget. Neither has been demonstrated to yield native code execution or privilege escalation.

## Reproduce offline

Requires Python 3.10+ and the local, immutable extracted segment images:

```sh
python tools/check_v10c_evidence.py --segments ./firmware --resources ./selected_resources
```

`--resources` is optional. The checker confirms SHA-256 and ten exact ARM instruction words. Its 320-byte boundary model **does not generate a malicious JAR or contact the phone**.

## Repository hygiene

`.gitignore` excludes copyrighted firmware images, extracted proprietary assets, Ghidra databases, temporary logs and credentials. Keep documentation, code, and small manifests under version control. During this review the GitHub default branch contained **only the README**, so no tracked files required deletion.

## Safety and scope

The analysis is static and read-only. No phone USB/service queries, flash writes, loader modifications, or experimental crashes. Labels `CONFIRMED`, `LIKELY`, and `HYPOTHESIS` in the report explicitly distinguish binary observations from exploit claims. Opening the bootloader or booting another OS remains a longer-term research goal, **not an achieved capability**.
