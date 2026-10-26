# 5-minute demo script (for the panel)

1. **Problem** – show a PC in the Sales VLAN opening a phishing-looking name (resolves to the attacker's IP).
2. **Dashboard** (`http://<ai-server>:8000`) – type `paypal-secure-login.xyz` in *Check a domain*:
   verdict BLOCK, score, and the **reasons** (keywords, brand impersonation, abused TLD).
3. **Live blocking** – on the PC run `nslookup <new-bad-domain>` twice: first answered, then `0.0.0.0` after the AI
   classified it. Point at the watcher log `[BLOCK] … [sync] …`.
4. **Zero false-block policy** – look up a normal-but-unusual name: it lands in *Review queue* as SUSPICIOUS and stays
   reachable; click **Allow** → added to overrides, blocklist reloads instantly.
5. **Evidence** – show `reports/roc_curve.png`, `confusion_matrix.png` and the honest limitations slide
   (names only, popular-site bias, reactive on first lookup) and the plan to retrain on local traffic.
