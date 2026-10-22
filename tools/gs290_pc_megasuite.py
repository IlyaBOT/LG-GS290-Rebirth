#!/usr/bin/env python3
"""GS290 PC MegaSuite: consolidate handset TXT, firmware and V10C ARM fuzzing.

Stdlib-only analysis; optional Unicorn campaign uses the separate MegaLab v8
harness and requires pip-installing its requirements. NO phone connection,
no firmware flashing, no exploit payload deployed to the device.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

EXPECTED_SEGMENTS = {
    "MPEH_segment0_46c00000.bin": (
        11184688, "0f9338bb6e6a80205ebd4a1d726a46eb039bbec9409b47e3138b079cffc3fa3c"),
    "MPEH_segment1_47800000.bin": (
        17272832, "f34f69dacfe5b570fafaa9e102196ebfa8fbeb9b01c5459cc0424661e67387a4"),
}

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def parse_phone(path):
    if not path:
        return {"status": "NOT PROVIDED"}
    txt = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    lines = txt.splitlines()
    pairs = {}
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            if key and len(key) < 90:
                pairs[key.strip()] = value.strip()
    status = "PHONE_JAVA_ONLY"
    if "=== SYSTEM AND VM ===" in txt or "GS290 J2ME MEGASUITE" in txt:
        status = "MEGASUITE_REPORT"
    notes = []
    if "MIDP: MIDP-2.1" in txt: notes.append("Device reports MIDP 2.1")
    if "FileConnection API: 1.0" in txt:
        notes.append("JSR-75 FileConnection 1.0 reported; export was possible")
    if "INFLATE RETURNED (NOT RCE)" in txt:
        notes.append("Safe DEFLATE control returned; does NOT prove native access")
    if "PREVIOUS RUN INTERRUPTED" in txt:
        notes.append("RMS interrupted; crash/restart alone NOT an exploit proof")
    if re.search(r"Native execution:\s*NOT PROVEN", txt, flags=re.I):
        notes.append("Device report explicitly marks native execution unproven")
    return {
        "status": status, "source": str(path), "sha256": sha256_bytes(txt.encode("utf-8")),
        "lines": len(lines), "properties": pairs, "notes": notes,
        "contains_native_pc_proof": False,
    }

def check_firmware(path):
    if not path:
        return {"status": "NOT PROVIDED", "note": "No V10C firmware to verify"}
    path = Path(path)
    records = {}
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        if path.is_dir():
            for base in EXPECTED_SEGMENTS:
                candidates = list(path.rglob(base))
                if len(candidates) != 1:
                    records[base] = {"ok": False, "error": "Expected exactly one matching file"}
                    continue
                data = candidates[0].read_bytes()
                size, expected = EXPECTED_SEGMENTS[base]
                records[base] = {
                    "size": len(data), "sha256": sha256_bytes(data),
                    "ok": len(data) == size and sha256_bytes(data) == expected,
                }
        elif zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for base, (size, expected) in EXPECTED_SEGMENTS.items():
                    candidates = [n for n in z.namelist() if Path(n).name == base]
                    if len(candidates) != 1:
                        records[base] = {"ok": False, "error": "Segment missing/ambiguous"}
                        continue
                    data = z.read(candidates[0])
                    records[base] = {
                        "size": len(data), "sha256": sha256_bytes(data),
                        "ok": len(data) == size and sha256_bytes(data) == expected,
                    }
        else:
            return {"status": "BAD SOURCE", "path": str(path)}
    return {
        "status": "V10C_VERIFIED" if all(x.get("ok") for x in records.values())
                  else "V10C_HASH_MISMATCH",
        "path": str(path), "segments": records,
        "note": "These are V10C hashes. A phone's V10k VM is not verified by this check.",
    }

def locate_run_report(path):
    """Read MegaLab report.json from a directory, a JSON file or a ZIP."""
    if not path:
        return None, None, None
    path = Path(path)
    if path.is_dir():
        choices = [path / "report.json", path / "jvm_mega_results" / "report.json"]
        for f in choices:
            if f.is_file():
                return json.loads(f.read_text(encoding="utf-8-sig")), f.parent, None
        raise FileNotFoundError("Missing report.json in " + str(path))
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8-sig")), path.parent, None
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        names = [x for x in z.namelist() if x.endswith("/report.json") or x == "report.json"]
        if len(names) != 1:
            z.close()
            raise ValueError("MegaLab ZIP must have exactly one report.json")
        return json.loads(z.read(names[0]).decode("utf-8-sig")), names[0].rsplit("/", 1)[0], z
    raise ValueError("Unknown MegaLab results source: " + str(path))

def summarize_arm(path, out):
    if not path:
        return {"status": "NOT PROVIDED", "native_code_execution": False}
    report, location, z = locate_run_report(path)
    try:
        cases = report.get("results", [])
        counts = Counter(row.get("status", "UNKNOWN") for row in cases)
        actual_oob = [row for row in cases
                      if (row.get("actual_fill_out_of_bounds_events") or 0) > 0]
        logical_only = [row for row in cases
                        if row.get("logical_bound_excess_events", 0) > 0
                        and not row.get("actual_fill_out_of_bounds_events", 0)]
        suspicious_lr = [x.get("case", "?") for x in cases
                         if x.get("saved_lr_preserved") is False]
        suspicious_pc = [x.get("case", "?") for x in cases
                         if (x.get("unexpected_pc_events") or 0) > 0]
        details = sorted(actual_oob, key=lambda x: (
            -(x.get("actual_fill_out_of_bounds_events") or 0), x.get("case", "")))
        top = [{
            "case": x.get("case"), "out_of_bounds_bytes": x.get("actual_fill_out_of_bounds_events"),
            "sha256": x.get("sha256"), "return_r0": x.get("return_r0"),
            "saved_lr_preserved": x.get("saved_lr_preserved"),
            "unexpected_pc_events": x.get("unexpected_pc_events"),
            "zlib_result": x.get("zlib"),
        } for x in details[:30]]
        subset = out / "interesting_cases.zip"
        with zipfile.ZipFile(subset, "w", zipfile.ZIP_DEFLATED) as bundle:
            for row in (details[:20] + cases[:1]):
                case = row.get("case")
                for ext in (".deflate", ".json", ".log"):
                    name = str(case) + ext
                    if z:
                        match = [n for n in z.namelist() if n.endswith("/" + name)]
                        if match: bundle.writestr(name, z.read(match[0]))
                    else:
                        p = Path(location) / name
                        if p.is_file(): bundle.write(p, name)
        return {
            "status": "OFFLINE_V10C_ONLY",
            "schema": report.get("schema"), "source": str(path),
            "requested": report.get("requested"), "completed": len(cases),
            "counts": dict(counts), "actual_oob_cases": len(actual_oob),
            "logical_only_cases": len(logical_only),
            "saved_lr_changes": suspicious_lr, "unexpected_pc_cases": suspicious_pc,
            "max_oob_bytes": max((x.get("actual_fill_out_of_bounds_events") or 0
                                  for x in cases), default=0),
            "top_cases": top, "subset": str(subset.name),
            "native_code_execution": False,
            "warning": "A function's R0=1 or a memory overwrite is not proof of PC control/RCE.",
        }
    finally:
        if z: z.close()

def launch_unicorn(zip_path, firmware, cases, jobs, seed, target):
    if not zip_path or not firmware:
        raise ValueError("--run-unicorn needs both --megalab-zip and --firmware")
    if not (6 <= cases <= 4096) or not (1 <= jobs <= 8):
        raise ValueError("Case count must be 6..4096; jobs 1..8")
    target = Path(target)
    work = target / "_megalab_engine"
    work.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        allowed = ("GS290_MegaLab/gs290_mega.py", "GS290_MegaLab/gs290_probe_v5.py",
                   "GS290_MegaLab/gs290_probe_v6_1.py", "GS290_MegaLab/gs290_probe_v7.py",
                   "GS290_MegaLab/gs290_unicorn.py")
        for member in allowed:
            data = z.read(member)
            (work / Path(member).name).write_bytes(data)
    cmd = [sys.executable, str(work / "gs290_mega.py"), "--firmware", str(Path(firmware).resolve()),
           "--out", str((target / "unicorn_runs").resolve()), "--cases", str(cases),
           "--jobs", str(jobs), "--seed", hex(seed), "--limit", "100000",
           "--case-timeout", "15"]
    print("[UNICON] Running existing MegaLab v8, cases=%d jobs=%d" % (cases, jobs))
    try:
        proc = subprocess.run(cmd, cwd=str(work), timeout=4 * 3600, check=False)
    except FileNotFoundError as e:
        raise RuntimeError("Python runner not found: " + str(e))
    if proc.returncode != 0:
        raise RuntimeError("MegaLab v8 exited %s. Check unicorn/capstone dependencies." %
                           proc.returncode)
    return target / "unicorn_runs"

def make_text(data):
    p, f, a = data["phone"], data["firmware"], data["unicorn"]
    lines = [
        "GS290 V10C/V10k MEGASUITE: PC + PHONE CONSOLIDATED REPORT",
        "Generated UTC: " + data["generated_utc"], "",
        "PHONE: " + p["status"],
        "  MIDP: " + p.get("properties", {}).get("MIDP", "not given"),
        "  CLDC: " + p.get("properties", {}).get("CLDC", "not given"),
        "  FileConnection: " + p.get("properties", {}).get("FileConnection API", "not given"),
        "  Evidence of native execution: NO",
    ]
    for note in p.get("notes", []): lines.append("  - " + note)
    lines += ["", "FIRMWARE: " + f["status"], "  " + f.get("note", ""),
              "", "OFFLINE ARM: " + a["status"],
              "  Cases completed: " + str(a.get("completed", 0)),
              "  Physical stack-array OOB cases: " + str(a.get("actual_oob_cases", 0)),
              "  Logical-only overruns: " + str(a.get("logical_only_cases", 0)),
              "  Unexpected PC events: " + str(a.get("unexpected_pc_cases", [])),
              "  Saved LR changes: " + str(a.get("saved_lr_changes", []))]
    lines.append("  Counts: " + str(a.get("counts", {})))
    for row in a.get("top_cases", [])[:20]:
        lines.append("  " + row["case"] + " OOB=" +
                     str(row["out_of_bounds_bytes"]) + " sha256=" + str(row["sha256"]))
    lines += ["", "INTERPRETATION",
              "  Real phone report is Java ME V10k; offline ARM source is V10C.",
              "  There is no direct binary equivalence shown for V10k.",
              "  Resource loading success proves Java access, not arbitrary native memory.",
              "  A native error or out-of-bounds write alone is not shell access or RCE.",
              "  Do not deploy malformed DEFLATE payloads to the handset.",
              ""]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phone-report", help="TXT exported by GS290 MIDlet")
    ap.add_argument("--firmware", help="Verified V10C firmware.zip or segments folder")
    ap.add_argument("--v8-report", help="Existing MegaLab v8 results ZIP/folder/report.json")
    ap.add_argument("--megalab-zip", help="Earlier GS290_MegaLab_v8_OneShot.zip")
    ap.add_argument("--run-unicorn", action="store_true",
                    help="Run new offline ARM campaign using existing MegaLab v8 scripts")
    ap.add_argument("--cases", type=int, default=1024)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0x290C)
    ap.add_argument("--out", default="GS290_PC_MegaSuite_Output")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    firmware = check_firmware(args.firmware)
    if args.run_unicorn and firmware["status"] != "V10C_VERIFIED":
        ap.error("Refusing ARM run: V10C segment SHA-256 verification failed")
    run = (launch_unicorn(args.megalab_zip, args.firmware, args.cases, args.jobs,
                         args.seed, out) if args.run_unicorn else args.v8_report)
    data = {
        "schema": "GS290 PC MegaSuite/1", "generated_utc": datetime.now(timezone.utc).isoformat(),
        "phone": parse_phone(args.phone_report), "firmware": firmware,
        "unicorn": summarize_arm(run, out),
        "result": "OFFLINE_MEMORY_SAFETY_RESEARCH; NATIVE_RCE_NOT_PROVEN",
    }
    (out / "MEGASUITE.json").write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
    (out / "MEGASUITE.txt").write_text(make_text(data), encoding="utf-8")
    with zipfile.ZipFile(out / "evidence_for_review.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("MEGASUITE.json", "MEGASUITE.txt", "interesting_cases.zip"):
            p = out / name
            if p.is_file(): z.write(p, name)
    print((out / "MEGASUITE.txt").read_text(encoding="utf-8")[:6500])
    print("[DONE] " + str(out))
    return 0

if __name__ == "__main__":
    sys.exit(main())
