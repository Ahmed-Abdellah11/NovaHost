"""Tail dnsmasq's query log, classify every NEW domain, keep the blocklist up to date.

    python -m nova.watcher                 # follow live log
    python -m nova.watcher --once FILE     # process an existing log file once (testing)
"""
from __future__ import annotations

import re
import sys
import time

from . import blocklist, config
from .service import Engine

QUERY_RE = re.compile(r"query\[(?:A|AAAA)\]\s+(\S+)\s+from\s+(\S+)")
FLUSH_EVERY = 2.0  # seconds: batch blocklist rewrites


def follow(path, poll=0.5):
    """Yield new lines forever; yield None when idle so the caller can flush work."""
    pos, inode = 0, None
    while True:
        try:
            st = path.stat()
            if inode is not None and (st.st_ino != inode or st.st_size < pos):
                pos = 0  # rotated / truncated
            inode = st.st_ino
            with open(path, "r", errors="ignore") as f:
                f.seek(pos)
                while True:
                    line = f.readline()
                    if not line or not line.endswith("\n"):
                        break  # EOF or half-written line: retry on the next poll
                    pos = f.tell()
                    yield line
        except FileNotFoundError:
            pass
        yield None
        time.sleep(poll)


def process(engine: Engine, lines, seen: set, flush_each_line=False) -> int:
    changed, last_sync, blocked_new = False, time.time(), 0
    for line in lines:
        if line is not None:
            m = QUERY_RE.search(line)
            if m:
                name, client = m.groups()
                if name not in seen and len(seen) < 500_000:
                    seen.add(name)
                    try:
                        res = engine.decide(name, record=True, client=client)
                    except ValueError:
                        continue
                    if res["verdict"] != "SAFE":
                        print(f"[{res['verdict']:<10}] {res['domain']}  score={res['score']:.2f} "
                              f"layer={res['layer']} client={client}", flush=True)
                    if res["verdict"] == "BLOCK":
                        changed = True
                        blocked_new += 1
        if changed and (flush_each_line or line is None or time.time() - last_sync >= FLUSH_EVERY):
            n, ok = blocklist.sync(engine.store)
            print(f"[sync] blocklist={n} domains, dnsmasq reloaded={ok}", flush=True)
            changed, last_sync = False, time.time()
    if changed:
        blocklist.sync(engine.store)
    return blocked_new


def main(argv):
    engine = Engine()
    blocklist.sync(engine.store)  # make sure the file exists before dnsmasq needs it
    if "--once" in argv:
        path = type(config.DNSMASQ_LOG)(argv[argv.index("--once") + 1])
        n = process(engine, path.read_text(errors="ignore").splitlines(keepends=True), set())
        print(f"[done] {n} new domains blocked")
        return
    print(f"[watcher] following {config.DNSMASQ_LOG}", flush=True)
    process(engine, follow(config.DNSMASQ_LOG), set())


if __name__ == "__main__":
    main(sys.argv[1:])
