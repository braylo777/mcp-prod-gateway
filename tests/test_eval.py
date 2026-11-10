import subprocess
import sys
from pathlib import Path


def test_corpus_eval_gate():
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, str(root / "eval" / "run_scan.py")], check=True, capture_output=True)
    import json
    r = json.loads((root / "results" / "scan_results.json").read_text())
    assert r["false_positive_rate"] == 0.0 and r["recall"] >= 0.9
