"""Decision engine.  Order of authority:

    1. admin override (SQLite)   2. allowlist file   3. denylist file
    4. known-bad feed            5. ML model
"""
from __future__ import annotations

from . import config, feeds
from .features import is_valid, normalize
from .predict import Classifier
from .store import Store, parents

LOCAL_SUFFIXES = (".local", ".lan", ".arpa", ".internal", ".home", ".localdomain")


def _read_list(name: str) -> set[str]:
    p = config.CONFIG_DIR / name
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.add(line)
    return out


class Engine:
    def __init__(self, clf: Classifier | None = None, store: Store | None = None):
        self.clf = clf or Classifier()
        self.store = store or Store()
        self.allow = _read_list("allowlist.txt")
        self.deny = _read_list("denylist.txt")
        self.feed = feeds.load()

    def _match(self, d: str, names: set[str]) -> bool:
        return any(p in names for p in parents(d))

    def decide(self, raw: str, record: bool = False, client: str | None = None) -> dict:
        d = normalize(raw)
        if not is_valid(d):
            raise ValueError(f"not a valid domain: {raw!r}")
        if d.endswith(LOCAL_SUFFIXES):
            return {"domain": d, "verdict": "SAFE", "score": 0.0, "reasons": [], "layer": "local"}

        ov = self.store.override_for(d)
        if ov:
            res = {"verdict": ov, "score": 1.0 if ov == "BLOCK" else 0.0,
                   "reasons": ["manual admin decision"], "layer": "override"}
        elif self._match(d, self.allow):
            res = {"verdict": "SAFE", "score": 0.0, "reasons": [], "layer": "allowlist"}
        elif self._match(d, self.deny):
            res = {"verdict": "BLOCK", "score": 1.0, "reasons": ["on local denylist"], "layer": "denylist"}
        elif self._match(d, self.feed):
            res = {"verdict": "BLOCK", "score": 1.0, "reasons": ["listed in known-bad threat feed"],
                   "layer": "feed"}
        else:
            m = self.clf.classify(d)
            res = {"verdict": m["verdict"], "score": m["score"], "reasons": m["reasons"], "layer": "model"}
        res["domain"] = d
        if record:
            self.store.record(d, res["verdict"], res["score"], res["reasons"], res["layer"], client)
        return res
