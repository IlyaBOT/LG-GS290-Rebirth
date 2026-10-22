#!/usr/bin/env python3
"""Self-contained smoke/regression checks for the PC MegaSuite CLI."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "gs290_pc_megasuite.py"

def test_pipeline():
    with tempfile.TemporaryDirectory() as root:
        path = Path(root)
        phone = path / "phone.txt"
        phone.write_text(
            "GS290 NATIVE ACCESS PROBE REPORT\nVersion: 0.2.0\n"
            "CLDC: CLDC-1.1\nMIDP: MIDP-2.1\n"
            "FileConnection API: 1.0\n"
            "DEFLATE result: INFLATE RETURNED (NOT RCE)\n"
            "Native execution: NOT PROVEN\n", encoding="utf-8")
        case = {
            "case": "synthetic_oob", "status": "INVESTIGATE_MEMORY_WRITE",
            "sha256": "a" * 64, "actual_fill_out_of_bounds_events": 3,
            "logical_bound_excess_events": 1, "saved_lr_preserved": True,
            "unexpected_pc_events": 0, "return_r0": "0x1", "zlib": "rejected",
        }
        baseline = {"case": "synthetic_control", "status": "RETURNED_SUCCESS",
                    "saved_lr_preserved": True, "unexpected_pc_events": 0}
        run = path / "v8.zip"
        with zipfile.ZipFile(run, "w") as z:
            z.writestr("jvm_mega_results/report.json",
                       json.dumps({"schema": "GS290 MegaLab v8", "requested": 2,
                                   "results": [baseline, case]}))
            z.writestr("jvm_mega_results/synthetic_oob.deflate", b"not a valid deflate")
        out = path / "out"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--phone-report", str(phone),
             "--v8-report", str(run), "--out", str(out)], capture_output=True,
            text=True, check=False)
        assert result.returncode == 0, result.stderr
        data = json.loads((out / "MEGASUITE.json").read_text())
        assert data["phone"]["status"] == "PHONE_JAVA_ONLY"
        assert data["unicorn"]["actual_oob_cases"] == 1
        assert data["unicorn"]["saved_lr_changes"] == []
        assert data["unicorn"]["max_oob_bytes"] == 3
        assert data["unicorn"]["native_code_execution"] is False
        with zipfile.ZipFile(out / "evidence_for_review.zip") as z:
            assert "MEGASUITE.json" in z.namelist()
            assert "interesting_cases.zip" in z.namelist()
        with zipfile.ZipFile(out / "interesting_cases.zip") as z:
            assert "synthetic_oob.deflate" in z.namelist()
        no_fw = data["firmware"]["status"]
        assert no_fw == "NOT PROVIDED", no_fw
        print("[PASS] PC MegaSuite accepts handset TXT and archived V8 reports")
        print("[PASS] Evidence ZIP and observed OOB counts independently verified")

if __name__ == "__main__":
    test_pipeline()
