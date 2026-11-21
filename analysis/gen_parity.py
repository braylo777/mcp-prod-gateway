"""Write tests/fixtures/parity_corpus.jsonl: Python v1 scanner output for every corpus tool.

The Rust test `tests/parity_corpus.rs` rebuilds the same cases from corpus/*.jsonl and must
give identical findings and fingerprints. `--check` exits 1 if the fixture is stale.
Each line: [case_id, fingerprint[:16], [[rule, severity, detail], ...] sorted].
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from mcpgw.scanner import fingerprint, scan_poisoning, scan_scopes  # noqa: E402

EXTERNAL = ["send_email", "get_forecast", "read_file", "create_issue", "search_web"]


def cases():
    for line in (ROOT / "corpus" / "attacks.jsonl").read_text().splitlines():
        a = json.loads(line)
        known = set(a["siblings"]) | set(a["external"]) | {a["tool"].get("name")}
        yield a["id"], a["tool"], known, a["scopes"]
        if a.get("approved"):
            yield a["id"] + "/approved", a["approved"], known, a["scopes"]
    for line in (ROOT / "corpus" / "benign.jsonl").read_text().splitlines():
        m = json.loads(line)
        names = {t.get("name") for t in m["tools"]} | set(EXTERNAL)
        for i, t in enumerate(m["tools"]):
            yield f"{m['id']}/{i}", t, names, m["scopes"].get(t.get("name"), [])


def row(cid, tool, known, scopes):
    f = scan_poisoning(tool, known) + scan_scopes(tool, scopes)
    return [cid, fingerprint(tool)[:16], sorted([x.rule, x.severity, x.detail] for x in f)]


def main():
    out = "".join(json.dumps(row(*c), ensure_ascii=False, separators=(",", ":")) + "\n" for c in cases())
    path = ROOT / "tests" / "fixtures" / "parity_corpus.jsonl"
    if "--check" in sys.argv:
        sys.exit(0 if path.exists() and path.read_text() == out else 1)
    path.write_text(out)
    print(f"{out.count(chr(10))} cases -> {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
