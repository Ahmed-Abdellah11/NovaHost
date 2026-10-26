"""Central configuration (override anything with environment variables)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = Path(os.getenv("NOVA_MODEL", ROOT / "models" / "model.joblib"))
DATA_DIR = Path(os.getenv("NOVA_DATA_DIR", ROOT / "var"))          # sqlite db + blocklist
CONFIG_DIR = Path(os.getenv("NOVA_CONFIG_DIR", ROOT / "config"))   # allowlist / denylist
DB_PATH = DATA_DIR / "nova.db"
BLOCKLIST_PATH = DATA_DIR / "blocklist.hosts"

DNSMASQ_LOG = Path(os.getenv("NOVA_DNSMASQ_LOG", "/var/log/dnsmasq.log"))
DNSMASQ_PID = Path(os.getenv("NOVA_DNSMASQ_PID", "/run/dnsmasq.pid"))

API_KEY = os.getenv("NOVA_API_KEY", "")  # if set, write endpoints require X-API-Key

# Optional threshold overrides (otherwise the values stored in the model file are used)
BLOCK_T = float(os.environ["NOVA_BLOCK_T"]) if "NOVA_BLOCK_T" in os.environ else None
SUSPECT_T = float(os.environ["NOVA_SUSPECT_T"]) if "NOVA_SUSPECT_T" in os.environ else None
