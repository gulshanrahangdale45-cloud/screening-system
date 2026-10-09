import os
from pathlib import Path


def _load_dotenv():
    """Read KEY=VALUE pairs from the project-root .env file (real env vars take priority)."""
    env_file = Path(__file__).resolve().parents[2] / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./screening.db")
    JWT_SECRET = _required("JWT_SECRET")
    JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "30"))
    FERNET_KEY = _required("FERNET_KEY")
    LEDGER_KEY = _required("LEDGER_SIGNING_KEY")
    LEDGER_SEAL_EVERY = int(os.getenv("LEDGER_SEAL_EVERY", "5"))
    UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
    MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "10"))
    DIGILOCKER_MODE = os.getenv("DIGILOCKER_MODE", "sandbox")
    DIGILOCKER_API_BASE = os.getenv("DIGILOCKER_API_BASE", "")
    DIGILOCKER_LOOKUP_PATH = os.getenv("DIGILOCKER_LOOKUP_PATH", "/lookup")
    SEED_PASSWORDS = {
        "admin": os.getenv("ADMIN_PASSWORD"),
        "officer": os.getenv("OFFICER_PASSWORD"),
        "auditor": os.getenv("AUDITOR_PASSWORD"),
    }


settings = Settings()