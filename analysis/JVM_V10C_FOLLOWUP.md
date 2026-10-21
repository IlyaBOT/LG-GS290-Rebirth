# JVM follow-up — LG GS290 V10C (offline ARM audit)

**Date:** 2026-10-21. The source is the uploaded `firmware.zip` and `manifests.zip` containing authentic extracted MPEH ARM segments and the FAT16 DFAT image. The physical handset runs **V10k CIS**, not this **V10C** factory image. No USB or device interaction occurred.

## New independent checks

- Restored **100 Java-related assets** from DFAT (Java_Original and Pxo/Java*) and checked each SHA-256 against the supplied `dfat_fs.json`.
- In native ARM segment0: `MIDP-2.1`. In segment1: `aroma.mvm.version` at VA `0x4786D198`, version string `13:15:34, Jun  7 2010 CVS TAG $Name$` at `0x4786D1AC`, `vm\\MVJar.c` at `0x47876F88`, and `vm\\MVerifier.c` at `0x4787A144`. This is the embedded AROMA Java VM with native ZIP and bytecode verification components, **not Java SE HotSpot**.
- All eight bundled `ams/M000..M007/jar` archives passed ZIP CRC testing, and all use method 8 (DEFLATE) among their entries. M006 Push e-mail and M007 Twitter have signed JAD metadata.

## Verified ARM control flow from ZIP/JAR reader to inflater

```text
0x4784203C  ZIP/JAR entry reader
  BL at 0x47842168 → 0x478421C8
0x478421C8  ZIP body reader, cmp method == 8 at 0x47842278
  BL at 0x478422E0 → 0x47877B00
0x47877B00  DEFLATE orchestration
  BL at 0x47877CCC → 0x47877130
0x47877130  block decode
  BL at 0x47877170 → 0x47876D0C
0x47876D0C  dynamic Huffman code-length decoder
```

These calls were re-read from actual segment1 ARM bytes and LLVM disassembly. This strengthens evidence that the suspect decoder participates in processing compressed JAR contents; it **does not** prove it is reachable by an unsigned JAR *before* validation.

## Native Huffman repeat bound — limited memory-safety candidate

ARM `0x47876E1C` sets a 320-byte area, `0x47876E20` selects `sp+12`, and `0x47876E28` initializes it. `HLIT + HDIST` has a maximum of 318. At `0x47876F14/24/28` the code computes and compares `new_end = r7 + repeat_count`. For `new_end > logical_end`, `0x47876F2C–58` only conditionally logs an error and **does not unconditionally return**. For repeat-symbol 16 it then calls byte fill `0x46D94800 → 0x46D80324`. Repeat symbols 17/18 do not take that fill branch because the buffer is initialized to zero.

Arithmetic-only boundary model: if the next repetition begins at index **317** and repeats the previous length **6** times, it writes indices **317..322**, which are **3 bytes beyond** a 320-byte buffer. The immediate adjacent variable starts at `sp+0x14c`; the modeled write does **not** reach the saved return address. There has been **no** CPU-only execution of an actual compressed input, guard-region check, demonstrated crash, or V10k test. Therefore status is **LIKELY memory-safety issue / RCE NOT PROVEN**, not an established exploit.

## Java trust domains and limits

`LGAPP/Media/Java_Original/cert/opn.pol`: untrusted MIDlets have one-shot file access prompts; operator/manufacturer domains have `allow`. `sys/cert.ini` recognizes `001. lge-java.crt` as operator/invisible. This does not grant arbitrary native ARM execution and is not an established signing bypass.

## Next binary targets

1. Perform **CPU-only ARM emulation** with protected/redzone memory around `0x47876D0C` and safe test input, then independently verify whether error handling stops the write.
2. Trace installer → ZIP entry read → signature verification order; inspect JAD processing `0x478295AE`.
3. Audit bytecode verifier `0x47878B14` and native bridges `0x47864520` (file system), `0x4786CEF0` (properties).
4. Audit policy parser `0x4782D8B8/0x4782EA6E/0x4782EC4C`, with attention to aliases and trust checks.
5. Do not generalize V10C results to the user's installed V10k before binary comparison.

Local source hashes: segment0 SHA-256 `0f9338bb6e6a80205ebd4a1d726a46eb039bbec9409b47e3138b079cffc3fa3c`, segment1 SHA-256 `f34f69dacfe5b570fafaa9e102196ebfa8fbeb9b01c5459cc0424661e67387a4`.
