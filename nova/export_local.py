"""Export domains your network actually uses (judged SAFE) as extra benign training data.

    python -m nova.export_local && python -m nova.data && python -m nova.train
"""
from .config import ROOT
from .store import Store

if __name__ == "__main__":
    s = Store()
    with s.lock:
        rows = s.conn.execute(
            "SELECT domain FROM decisions WHERE verdict='SAFE' AND layer IN ('model','allowlist')").fetchall()
        rows += s.conn.execute("SELECT domain FROM overrides WHERE verdict='SAFE'").fetchall()
    out = ROOT / "data" / "local_benign.txt"
    out.write_text("\n".join(sorted({r[0] for r in rows})) + "\n")
    print(f"[+] {len(rows)} domains -> {out}")
