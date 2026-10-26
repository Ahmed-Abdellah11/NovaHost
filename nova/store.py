"""SQLite persistence: decisions made by the engine + manual admin overrides."""
from __future__ import annotations

import json
import sqlite3
import threading
import time

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions(
  domain TEXT PRIMARY KEY, verdict TEXT NOT NULL, score REAL, reasons TEXT, layer TEXT,
  client TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS overrides(
  domain TEXT PRIMARY KEY, verdict TEXT NOT NULL, ts REAL);
CREATE INDEX IF NOT EXISTS idx_dec_verdict ON decisions(verdict);
"""


def parents(domain: str):
    """a.b.c.com -> a.b.c.com, b.c.com, c.com (never the bare TLD)."""
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


class Store:
    def __init__(self, path=config.DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)

    # ---- decisions
    def record(self, domain, verdict, score, reasons, layer, client=None):
        now = time.time()
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO decisions(domain,verdict,score,reasons,layer,client,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET verdict=excluded.verdict, score=excluded.score,
                     reasons=excluded.reasons, layer=excluded.layer,
                     client=COALESCE(excluded.client, client), last_seen=excluded.last_seen""",
                (domain, verdict, score, json.dumps(reasons), layer, client, now, now))

    @staticmethod
    def _row(r):
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        return d

    def get(self, domain):
        with self.lock:
            r = self.conn.execute("SELECT * FROM decisions WHERE domain=?", (domain,)).fetchone()
        return self._row(r) if r else None

    def recent(self, limit=50):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM decisions ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(r) for r in rows]

    def review_queue(self, limit=100):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM decisions WHERE verdict='SUSPICIOUS' ORDER BY score DESC LIMIT ?",
                (limit * 3,)).fetchall()
        out = [self._row(r) for r in rows if self.override_for(r["domain"]) is None]
        return out[:limit]

    def stats(self):
        with self.lock:
            counts = {r["verdict"]: r["n"] for r in self.conn.execute(
                "SELECT verdict, COUNT(*) n FROM decisions GROUP BY verdict")}
            ov = self.conn.execute("SELECT COUNT(*) FROM overrides").fetchone()[0]
        return {"total": sum(counts.values()), "by_verdict": counts, "overrides": ov,
                "blocked_now": len(self.blocked_domains())}

    # ---- overrides
    def set_override(self, domain, verdict):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO overrides(domain,verdict,ts) VALUES(?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET verdict=excluded.verdict, ts=excluded.ts",
                (domain, verdict, time.time()))

    def override_for(self, domain):
        ps = list(parents(domain))
        if not ps:
            return None
        with self.lock:
            rows = {r["domain"]: r["verdict"] for r in self.conn.execute(
                f"SELECT domain, verdict FROM overrides WHERE domain IN ({','.join('?' * len(ps))})", ps)}
        for p in ps:  # most specific first
            if p in rows:
                return rows[p]
        return None

    def blocked_domains(self) -> list[str]:
        with self.lock:
            bad = [r[0] for r in self.conn.execute("SELECT domain FROM decisions WHERE verdict='BLOCK'")]
            forced = [r[0] for r in self.conn.execute("SELECT domain FROM overrides WHERE verdict='BLOCK'")]
            safe = {r[0] for r in self.conn.execute("SELECT domain FROM overrides WHERE verdict='SAFE'")}
        keep = {d for d in bad if not any(p in safe for p in parents(d))}
        return sorted(keep | set(forced))
