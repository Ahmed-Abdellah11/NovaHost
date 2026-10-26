"""Download public domain lists and build a labelled dataset.

    python -m nova.data            # downloads (cached in data/raw) and writes data/dataset.csv.gz

Sources (all public GitHub-hosted lists):
  benign    : zer0h/top-1000000-domains (top 100k)  +  opendns/public-domain-lists (top 10k)
  malicious : mitchellkrogza/Phishing.Database (active phishing domains)
              StevenBlack/hosts (malware / adware / tracker domains)
"""
from __future__ import annotations

import random
import re
import urllib.request
from pathlib import Path

import pandas as pd

from .config import ROOT
from .features import is_valid, normalize, registered_domain

RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "dataset.csv.gz"
GH = "https://raw.githubusercontent.com/"
SOURCES = {
    "benign_top100k": GH + "zer0h/top-1000000-domains/master/top-100000-domains",
    "benign_opendns": GH + "opendns/public-domain-lists/master/opendns-top-domains.txt",
    "phishing": GH + "mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "hosts": GH + "StevenBlack/hosts/master/hosts",
}
# Benign list holds bare registered domains; real traffic has subdomains too. Without this
# augmentation "has a subdomain" would trivially separate the two classes.
PREFIXES = ["www", "mail", "m", "api", "cdn", "login", "accounts", "support", "shop", "blog",
            "static", "app", "secure", "my", "portal", "docs", "img", "news", "web", "online"]
HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
              "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
              "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}


def download() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        p = RAW / f"{name}.txt"
        if p.exists() and p.stat().st_size > 0:
            continue
        print(f"[download] {name}")
        req = urllib.request.Request(url, headers={"User-Agent": "nova-classifier/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            p.write_bytes(r.read())


def _read(name: str, hosts_format: bool = False) -> list[str]:
    out = []
    for line in (RAW / f"{name}.txt").read_text(errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if hosts_format:
            parts = line.split()
            if len(parts) < 2:
                continue
            line = parts[1]
        d = normalize(line)
        if d and d not in HOSTS_SKIP and is_valid(d) and len(d) <= 100:
            out.append(d)
    return list(dict.fromkeys(out))  # de-duplicate, keep order


def build(n_benign: int = 70_000, n_phish: int = 55_000, n_hosts: int = 15_000, seed: int = 42) -> pd.DataFrame:
    random.seed(seed)
    download()
    benign_raw = list(dict.fromkeys(_read("benign_top100k") + _read("benign_opendns")))
    benign_reg = {registered_domain(d) for d in benign_raw}

    phish = [d for d in _read("phishing") if registered_domain(d) not in benign_reg]
    hosts = [d for d in _read("hosts", hosts_format=True) if registered_domain(d) not in benign_reg]
    random.shuffle(phish)
    phish = phish[:n_phish]
    random.shuffle(hosts)
    hosts = hosts[:n_hosts]

    random.shuffle(benign_raw)
    benign = []
    for d in benign_raw[:n_benign]:
        if random.random() < 0.35:
            d = f"{random.choice(PREFIXES)}.{d}"
        benign.append(d)

    local = ROOT / "data" / "local_benign.txt"   # exported from your own DNS traffic (see README)
    local_rows = []
    if local.exists():
        local_rows = [(n, 0, "local_benign") for n in map(normalize, local.read_text().split())
                      if is_valid(n)]
    rows = (local_rows + [(d, 0, "benign") for d in benign] + [(d, 1, "phishing") for d in phish]
            + [(d, 1, "hosts") for d in hosts])
    df = pd.DataFrame(rows, columns=["domain", "label", "source"]).drop_duplicates("domain")
    df["group"] = df["domain"].map(registered_domain)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    df.to_csv(OUT, index=False)
    print(df.groupby(["label", "source"]).size().to_string())
    print(f"[+] {len(df)} rows -> {OUT}")
    return df


if __name__ == "__main__":
    build()
