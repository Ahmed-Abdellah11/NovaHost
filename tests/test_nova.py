import os, tempfile
tmp = tempfile.mkdtemp()
os.environ["NOVA_DATA_DIR"] = tmp          # isolate DB + blocklist from real data
os.environ["NOVA_DNSMASQ_PID"] = tmp + "/none.pid"

import pytest
from fastapi.testclient import TestClient

from nova.api import app
from nova.features import normalize, registered_domain, explain


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_normalize_and_registered():
    assert normalize("HTTPS://User@Login.Example.com:8080/a?b=1") == "login.example.com"
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("a.b.example.com") == "example.com"


def test_explain_flags_phishing_patterns():
    why = " ".join(explain("login.paypal.com.verify-account.top"))
    assert "keywords" in why and "brand" in why


def test_health(client):
    r = client.get("/health").json()
    assert r["status"] == "ok" and r["feed_size"] > 0


def test_allowlist_beats_model(client):
    assert client.post("/classify", json={"domain": "mail.google.com"}).json()["layer"] == "allowlist"


def test_obvious_phishing_is_blocked(client):
    r = client.post("/classify", json={"domain": "paypal-secure-login-verify.xyz"}).json()
    assert r["verdict"] in ("BLOCK", "SUSPICIOUS") and r["reasons"]


def test_normal_looking_sites_are_never_auto_blocked(client):
    # Long-tail small-business names may land in SUSPICIOUS (review queue) but must not be BLOCKed.
    names = ["daily-news.com", "student-portal.edu.eg", "cloud-studio.io", "techcity.org",
             "mohamed-photography.com", "cairo-hospital.org", "shopping-hub.com", "gamerzone.io"]
    verdicts = [client.post("/classify", json={"domain": d}).json()["verdict"] for d in names]
    assert "BLOCK" not in verdicts


def test_invalid_input(client):
    assert client.post("/classify", json={"domain": "not a domain!!"}).status_code == 422


def test_override_flow_and_blocklist(client):
    d = "totally-new-site-123.com"
    client.post("/classify?record=true", json={"domain": d})
    assert client.post("/deny", json={"domain": d}).json()["verdict"] == "BLOCK"
    assert f"0.0.0.0 {d}" in client.get("/blocklist").text
    client.post("/allow", json={"domain": d})
    assert f"0.0.0.0 {d}" not in client.get("/blocklist").text
    assert client.post("/classify", json={"domain": "x." + d}).json()["layer"] == "override"


def test_batch(client):
    r = client.post("/classify/batch", json={"domains": ["google.com", "bad bad"]}).json()
    assert r[0]["verdict"] == "SAFE" and r[1]["verdict"] == "INVALID"


def test_dashboard_served(client):
    assert "Nova Host" in client.get("/").text
