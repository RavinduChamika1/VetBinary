"""
config.py — centralised settings loaded from environment variables.
All keys have sensible defaults so the app starts even with an empty .env
(though functionality will be limited without API keys).
"""
import os
from dotenv import load_dotenv

from pathlib import Path

# Load .env from backend dir, parent VetBinary dir, or current working dir
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
load_dotenv()

# ── API keys ────────────────────────────────────────────────────────────────
VT_API_KEY: str = os.getenv("VT_API_KEY", "")
ANYRUN_API_KEY: str = os.getenv("ANYRUN_API_KEY", "")
HYBRID_ANALYSIS_API_KEY: str = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "") or os.getenv("GEMINI_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")

# ── Storage & Paths ──────────────────────────────────────────────────────────
LOCAL_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
LOCAL_DATA_DIR.mkdir(parents=True, exist_ok=True)
_in_docker = os.path.exists("/data") and os.access("/data", os.W_OK)

raw_db = os.getenv("DATABASE_URL", "")
if not _in_docker and (not raw_db or "/data" in raw_db):
    DATABASE_URL = f"sqlite+aiosqlite:///{LOCAL_DATA_DIR.as_posix()}/vetbinary.db"
elif "sqlite://" in raw_db and "aiosqlite" not in raw_db:
    DATABASE_URL = raw_db.replace("sqlite://", "sqlite+aiosqlite://")
else:
    DATABASE_URL = raw_db or f"sqlite+aiosqlite:///{LOCAL_DATA_DIR.as_posix()}/vetbinary.db"

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "650"))
MAX_UPLOAD_BYTES: int = MAX_UPLOAD_MB * 1024 * 1024

# ── External API constants ───────────────────────────────────────────────────
VT_FREE_SUBMISSION_LIMIT_MB: int = 32          # VT free tier max upload
ANYRUN_FILE_SIZE_LIMIT_MB: int = 16            # ANY.RUN community limit
HYBRID_ANALYSIS_FILE_SIZE_LIMIT_MB: int = 100  # Hybrid Analysis max
HYBRID_ANALYSIS_MONTHLY_QUOTA: int = 30        # free plan monthly cap

# ── Upstream URLs ────────────────────────────────────────────────────────────
VT_BASE_URL = "https://www.virustotal.com/api/v3"
ANYRUN_BASE_URL = "https://api.any.run/v1"
HYBRID_ANALYSIS_BASE_URL = "https://hybrid-analysis.com/api/v2"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ── Upload temp directory ────────────────────────────────────────────────────
if not _in_docker and ("/data" in os.getenv("UPLOAD_TEMP_DIR", "/data/uploads")):
    UPLOAD_TEMP_DIR = str(LOCAL_DATA_DIR / "uploads")
else:
    UPLOAD_TEMP_DIR = os.getenv("UPLOAD_TEMP_DIR", "/data/uploads" if _in_docker else str(LOCAL_DATA_DIR / "uploads"))
os.makedirs(UPLOAD_TEMP_DIR, exist_ok=True)
