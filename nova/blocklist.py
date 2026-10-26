"""Write the dnsmasq hosts-format blocklist and tell dnsmasq to reload it."""
from __future__ import annotations

import os
import signal

from . import config
from .store import Store


def write(store: Store, path=config.BLOCKLIST_PATH) -> int:
    domains = store.blocked_domains()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("".join(f"0.0.0.0 {d}\n" for d in domains))
    os.replace(tmp, path)  # atomic: dnsmasq never sees a half-written file
    return len(domains)


def reload_dnsmasq() -> bool:
    try:
        os.kill(int(config.DNSMASQ_PID.read_text().strip()), signal.SIGHUP)
        return True
    except (FileNotFoundError, ProcessLookupError, ValueError, PermissionError):
        return False


def sync(store: Store) -> tuple[int, bool]:
    n = write(store)
    return n, reload_dnsmasq()


if __name__ == "__main__":
    n, ok = sync(Store())
    print(f"[+] {n} domains written to {config.BLOCKLIST_PATH}; dnsmasq reloaded: {ok}")
