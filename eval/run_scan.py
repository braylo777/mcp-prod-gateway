"""Run the scanner over the labelled corpus and write results/scan_results.json."""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.corpus import CORPUS  # noqa: E402
from mcpgw.scanner import HIGH, MEDIUM, scan_poisoning, scan_scopes  # noqa: E402

KNOWN = {"send_email", "get_forecast"}  # tools from other servers in the same session

rows, fam = [], defaultdict(lambda: [0, 0])
tp = fp = tn = fn = 0
for item in CORPUS:
    t = item["tool"]
    f = scan_poisoning(t, KNOWN | {t["name"]}) + scan_scopes(t, item["scopes"])
    flagged = any(x.severity in (HIGH, MEDIUM) for x in f)
    lab = item["label"]
    tp += lab and flagged; fn += lab and not flagged
    fp += (not lab) and flagged; tn += (not lab) and not flagged
    if lab:
        fam[item["family"]][0] += flagged; fam[item["family"]][1] += 1
    rows.append({"tool": t["name"], "label": lab, "family": item["family"], "flagged": flagged,
                 "rules": sorted({x.rule for x in f})})
out = {"n": len(CORPUS), "malicious": tp + fn, "benign": tn + fp,
       "tp": tp, "fp": fp, "tn": tn, "fn": fn,
       "recall": round(tp / (tp + fn), 3), "precision": round(tp / (tp + fp), 3) if tp + fp else None,
       "false_positive_rate": round(fp / (fp + tn), 3),
       "per_family": {k: f"{a}/{b}" for k, (a, b) in sorted(fam.items())},
       "misses": [r["tool"] for r in rows if r["label"] and not r["flagged"]],
       "false_positives": [r["tool"] for r in rows if not r["label"] and r["flagged"]],
       "rows": rows}
(ROOT / "results").mkdir(exist_ok=True)
(ROOT / "results" / "scan_results.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps({k: v for k, v in out.items() if k != "rows"}, indent=2))
