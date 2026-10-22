#!/usr/bin/env python3
"""Package a CLDC phone JAR with a *lazy* ZIP/DEFLATE resource test.

Default "control" makes a fully valid JAR and can be used on a handset.
Experimental "huffman-oob" injects an intentionally INVALID raw DEFLATE entry
reproducing a 3-byte stack-local OOB in V10C Unicorn. It is UNSAFE for a phone:
the actual V10k handset firmware has not been checked. Requires explicit opt-in.

The experiment is not a native code execution exploit. A crash/interruption
does not establish PC control, system privilege, or command execution.
"""
import argparse
from pathlib import Path
import hashlib
import struct
import zipfile
import zlib

RESOURCE = "GS290ProbePayload.bin"
# 78-byte dynamic Huffman testcase: physical_318_repeat6_nonzero (Probe v7).
# SHA256: 702e33e26902e549fad41c7f56fdd4b4319f5616c8164bfe2e7b10bc966305a2
MALFORMED = bytes.fromhex(
    "eddf05090000000020ffaf76980d000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000"
)
SAFE_DATA = b"LG GS290 DEFLATE RESOURCE CHECK: JAVA RETURNED SAFELY.\n"

def raw_compress(data):
    obj = zlib.compressobj(6, zlib.DEFLATED, -15)
    return obj.compress(data) + obj.flush()

def zip_write_entries(entries, target):
    # No data descriptors; manifest is first; central dir entries have local offsets.
    with target.open("wb") as f:
        central = []
        for name, data, packed, checksum, original_size in entries:
            fname = name.encode("utf-8")
            if len(fname) > 65535:
                raise ValueError("invalid ZIP name")
            offset = f.tell()
            local = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 8, 0, 0,
                                checksum, len(packed), original_size, len(fname), 0)
            f.write(local + fname + packed)
            central.append(struct.pack("<IHHHHHHIIIHHHHHII",
                0x02014b50, 20, 20, 0, 8, 0, 0, checksum, len(packed),
                original_size, len(fname), 0, 0, 0, 0, 0, offset) + fname)
        central_pos = f.tell()
        for entry in central:
            f.write(entry)
        central_len = f.tell() - central_pos
        if len(central) > 65535:
            raise ValueError("too many ZIP entries")
        f.write(struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(central),
                            len(central), central_len, central_pos, 0))

def fix_jad(base_jad, output, jar_name, jar_size):
    if base_jad is None:
        raise ValueError("pass existing build JAD path")
    lines = base_jad.read_text(encoding="utf-8-sig").splitlines()
    result = [line for line in lines
              if not line.startswith("MIDlet-Jar-URL:")
              and not line.startswith("MIDlet-Jar-Size:")]
    result += ["MIDlet-Jar-URL: " + jar_name,
               "MIDlet-Jar-Size: " + str(jar_size)]
    output.write_bytes(("\r\n".join(result) + "\r\n").encode("utf-8"))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True, help="Valid CLDC JAR from phonebuild")
    p.add_argument("--jad", type=Path, required=True, help="JAD accompanying --input")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--mode", choices=["control", "huffman-oob"], default="control")
    p.add_argument("--i-accept-phone-crash-risk", action="store_true")
    args = p.parse_args()
    if args.mode == "huffman-oob" and not args.i_accept_phone_crash_risk:
        p.error("malformed DEFLATE test requires --i-accept-phone-crash-risk")
    if args.out.resolve() == args.input.resolve():
        p.error("--out must not overwrite the source JAR")
    args.out.parent.mkdir(parents=True, exist_ok=True)

    if len(MALFORMED) != 78 or hashlib.sha256(MALFORMED).hexdigest() != \
        "702e33e26902e549fad41c7f56fdd4b4319f5616c8164bfe2e7b10bc966305a2":
        raise RuntimeError("experimental corpus changed unexpectedly")
    data = []
    with zipfile.ZipFile(args.input) as zin:
        for info in zin.infolist():
            if info.is_dir() or info.filename == RESOURCE:
                continue
            blob = zin.read(info.filename)
            data.append((info.filename, blob, raw_compress(blob),
                         zlib.crc32(blob) & 0xffffffff, len(blob)))
    # Keep the resource entry at the very end of the ZIP.
    if args.mode == "control":
        blob = SAFE_DATA
        packed = raw_compress(blob)
        crc = zlib.crc32(blob) & 0xffffffff
        uncompressed_len = len(blob)
    else:
        blob = b""  # not actually decodable; never claim accepted by zipfile
        packed = MALFORMED
        crc = 0
        uncompressed_len = 4096
    data.append((RESOURCE, blob, packed, crc, uncompressed_len))
    # The ZIP directory is structurally valid in both modes. The malformed
    # experiment will be rejected by standards-compliant DEFLATE parsers.
    zip_write_entries(data, args.out)
    jad_path = args.out.with_suffix(".jad")
    fix_jad(args.jad, jad_path, args.out.name, args.out.stat().st_size)

    with zipfile.ZipFile(args.out) as z:
        assert RESOURCE in z.namelist()
        assert "META-INF/MANIFEST.MF" in z.namelist()
        assert "org/ilyabot/gs290/NativeAccessProbe.class" in z.namelist()
        if args.mode == "control":
            assert z.read(RESOURCE) == SAFE_DATA
            assert z.testzip() is None
    print("[MODE]", args.mode)
    print("[JAR]", args.out, args.out.stat().st_size)
    print("[JAD]", jad_path)
    print("[PAYLOAD]", len(packed), "compressed bytes")
    print("[CAUTION]", "This is a ZIP inflater experiment; native RCE is not demonstrated.")

if __name__ == "__main__":
    main()
