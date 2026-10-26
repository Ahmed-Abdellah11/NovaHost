"""Known-bad domain feed (threat-intel layer that sits in front of the ML model).

    python -m nova.feeds        # (re)download public feeds -> models/feed.txt.gz
"""
from __future__ import annotations

import gzip
import os
from pathlib import Path

from .config import ROOT

FEED_PATH = Path(os.getenv("NOVA_FEED", ROOT / "models" / "feed.txt.gz"))


def load(path: Path = FEED_PATH) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    with gzip.open(path, "rt") as f:
        return frozenset(line.strip() for line in f if line.strip())


def update(path: Path = FEED_PATH) -> int:
    from .data import _read, download
    from .features import registered_domain
    download()
    benign_reg = {registered_domain(d) for d in _read("benign_top100k") + _read("benign_opendns")}
    bad = set(_read("phishing")) | set(_read("hosts", hosts_format=True))
    bad = sorted(d for d in bad if registered_domain(d) not in benign_reg)
    with gzip.open(path, "wt") as f:
        f.write("\n".join(bad))
    print(f"[+] feed: {len(bad)} known-bad domains -> {path}")
    return len(bad)


if __name__ == "__main__":
    update()
