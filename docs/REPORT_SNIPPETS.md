# Ready-to-paste paragraphs (English)

**Section 2 – Solution**
We added an AI-based website classifier to the DNS layer. Instead of maintaining block lists by hand, a machine-learning
model scores every domain requested on the network using lexical features (length, entropy, keywords, TLD, brand
impersonation) and character n-grams. Domains above a calibrated threshold are blocked automatically, grey-zone domains
are sent to an administrator review queue, and trusted domains are protected by an allowlist.

**Section 3 – Prototype**
The AI DNS Server is a Docker node in GNS3 placed in the Data Center zone. It runs dnsmasq, a log-watching service and a
REST API with an admin dashboard. All VLANs receive its address through DHCP, and an ACL forces clients to use it as their
only DNS server. When the model flags a domain, the blocklist is rewritten and dnsmasq reloads it, after which the domain
resolves to 0.0.0.0.

**Section 4 – Testing and results**
The model was trained on about 140,000 public domains (70,000 popular benign sites, 55,000 phishing domains and 15,000
malware/tracker domains) and evaluated on a held-out test set split by registered domain to avoid leakage. The ensemble
reached an AUC of 0.946. At the blocking threshold it achieved 99.1 % precision and 60.0 % recall with a 0.52 %
false-positive rate; including the suspicious band, recall rose to 74.1 % at a 2.9 % false-positive rate. Because
lexical analysis cannot inspect page content, the system is used as one defence layer alongside ACLs, the WAF and a
known-bad threat feed, and uncertain domains are reviewed by an administrator rather than blocked.
