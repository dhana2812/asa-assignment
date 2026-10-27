import os


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")


def _require_env(name: str) -> str:
    """Raise at import time if a required secret env var is absent.

    Prevents accidental startup with a missing or empty secret, ensuring
    the application fails fast rather than running with insecure defaults
    (CWE-798 / VT-02 remediation).
    """
    raise RuntimeError(
        f"Required environment variable '{name}' is not set. "
        "In production, inject secrets via AWS Secrets Manager (see terraform/secrets.tf). "
        "For local development, export the variable before starting the app: "
        f"  export {name}=<value>"
    )


# ---------------------------------------------------------------------------
# Secrets -- sourced strictly from environment variables at runtime.
# No hardcoded fallback values; startup fails fast if any required secret is absent.
# ---------------------------------------------------------------------------
SECRET_KEY: str = os.environ.get("SECRET_KEY") or _require_env("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database credentials
DB_USER = os.getenv("DB_USER", "vulntracker_app")
DB_PASSWORD: str = os.environ.get("DB_PASSWORD") or _require_env("DB_PASSWORD")

# Internal service API key
ADMIN_API_KEY: str = os.environ.get("ADMIN_API_KEY") or _require_env("ADMIN_API_KEY")

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")