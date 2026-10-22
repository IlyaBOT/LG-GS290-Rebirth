# AROMA VM Huffman V10C evidence — 2026-10-23

Results are from user-run Unicorn tests against actual extracted V10C MPEH
ARM code with synthetic callback/allocator, not a full phone emulator.

| Test | Observed result |
|---|---|
| Probe v5, valid DEFLATE | ARM returns R0=1, two allocated Huffman tables |
| Probe v7 structural input | Native stores 1–3 bytes beyond 320-byte array |
| MegaLab v8 (768 cases) | 14 physical overruns; 133 logical-only overruns |
| Saved LR | Never altered in 768 cases |
| Unexpected PC transfer | None |
| Native RCE | Not proven |
| V10k handset | Not compared/tested |

Instructions: 0x46D801B0, 0x46D801B4, 0x46D801BC.
Adjacent 32-bit stack local in one case:
02 00 00 00 -> 01 01 01 00.

Do not interpret this as privilege escalation, arbitrary memory access
or OS command execution on the physical device.
