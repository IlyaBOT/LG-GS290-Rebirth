# V10C Huffman 3-byte OOB: post-write variable liveness

Evidence checked on 2026-10-26:
- Authentic `firmware/MPEH_segment1_47800000.bin` from owner-provided V10C firmware ZIP
- ARM-mode disassembly of native function `0x47876D0C`
- Owner-run `jvm_v7_targeted.zip`, including all 3 physical OOB cases
- Owner-run `jvm_mega_results.zip` and current GS290 MegaSuite v0.2.0 TXT

## Confirmed target of physical overwrite

The local array starts at `SP+12` and covers 320 bytes, ending immediately
before `SP+0x14c`. This next four-byte slot holds an **unsigned Huffman
bit-width/count** (originally a halfword read from the first allocated tree),
not saved LR or a function pointer:

```armasm
0x47876E18  LDRH R3, [R9]
0x47876E24  STR  R3, [SP, #0x14C]
0x47876E74  LDR  R3, [SP, #0x14C]
0x47876E9C  LDR  R3, [SP, #0x14C]
```

The latter two reads are in the **decode loop preceding the repeat fill**.
For `physical_318_repeat6_nonzero`, the existing v7 trace records three
byte-wise writes past the physical boundary, changing `02 00 00 00`
to `01 01 01 00`. That is still a real stack-object corruption.

## Relevant post-overflow control flow

```armasm
0x4787702C BL 0x46D94800      ; native byte fill; actual overflow
0x47877030 LDR R7, [SP,#0x164] ; restore new_end
0x47877034 LDR R1, [SP,#8]     ; logical_end
0x47877038 CMP R7, R1
0x4787703C BLO 0x47876E4C     ; only loop back if new_end < logical_end
0x47877040 ...                 ; build final Huffman trees
0x478770C4 MOV R0, #1
0x478770C8 ADD SP, SP, #380
0x478770CC POP {R4-R11,PC}
```

v7 bound-trace evidence:

| Case | new_end | logical_end | Actual bytes outside array |
|---|---|---|---:|
| physical_316_repeat6_nonzero | 0x7001efad | 0x7001efa8 | 1 |
| physical_318_repeat6_nonzero | 0x7001efaf | 0x7001efaa | 3 |
| physical_318_repeat6_zero | 0x7001efaf | 0x7001efaa | 3 |

For all three, `new_end > logical_end`: the decoder does **not** branch
back to the code that reads the corrupted `SP+0x14c` value. Static
disassembly finds no read of that stack slot after `0x4787703C`
before successful function return. In the **confirmed v7 paths**, this
local appears dead when it is corrupted.

### Interpretation

- **CONFIRMED:** physically out-of-bounds 1–3 byte writes in V10C ARM code
  running in a synthetic Unicorn environment.
- **STRONG EVIDENCE FOR THIS PATH:** adjacent overwritten bit-width is not
  consumed after the final Huffman length repeat. The observed 3-byte
  corruption does **not** constitute a known exploitation primitive.
- **NOT PROVEN:** arbitrary pointer writes, PC/LR control, native RCE,
  triggering the same defect on the handset's different V10k firmware.

This reanalysis is narrower and more rigorous than the original hypothesis
that corruption of `SP+0x14c` might influence a subsequent table lookup.
It could do so only if some other execution path consumes the slot after
a fill. That has not been observed.

## Next milestone: investigate end-to-end reachability, not more blind repeats

1. Obtain a legitimate, read-only V10k firmware image for byte-for-byte
   comparison of the relevant JAR reader → DEFLATE call chain against V10C.
2. Trace (offline) whether untrusted JAR resources reach the native decoder
   and at what stage: install-time extraction, runtime resource open, or
   class loader. A **valid control resource** working on V10k does not
   automatically establish dynamic-Huffman malformed input reachability.
3. Add memory-read hooks to the isolated Unicorn decoder and check for reads
   from `SP+0x14c` **after** the first OOB write, including error paths.
   Capture full control-flow traces rather than infer exploitability from R0.
4. If the damaged local stays dead and no other side effects are found,
   stop prioritizing this particular repeat overflow. Audit the broader
   native ZIP entry reader and the AROMA bytecode verifier next, and retain
   the OOB result as a confirmed, potentially low-impact memory-safety bug.

## Current physical phone report

`GS290_Mega_1948778.txt` reports 49 checks: 45 PASS, zero FAIL,
four N/A and RMS `MEGA:FINISHED`. Safe J2ME resource reads returned
55 bytes/checksum 3620 twice, and FileConnection API 1.0 reported eight
filesystem roots. No malformed DEFLATE test was run on the phone, and
there is no low-level native proof. `checkPermission` reports file
read/write DENIED (0), despite successful TXT export, so real file access
and preflight permission reporting must be distinguished.
