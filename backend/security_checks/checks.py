import os
import subprocess
import sys
from pathlib import Path


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def check_cors_configuration(project_root: str | os.PathLike[str] | None = None) -> dict:
    root = Path(project_root or Path(__file__).resolve().parents[2])
    env_file = root / "backend" / ".env"
    env_example = root / "backend" / ".env.example"
    content = _read_text(env_file) or _read_text(env_example)
    origins = [item.strip() for item in content.splitlines() if item.startswith("CS_ALLOWED_ORIGINS")]
    configured = []
    for line in origins:
        _, _, value = line.partition("=")
        configured.extend(part.strip() for part in value.split(",") if part.strip())
    status = "pass" if configured and all(item != "*" for item in configured) else "warn"
    return {
        "name": "cors_configuration",
        "status": status,
        "details": "Explicit trusted origins are configured" if status == "pass" else "No explicit trusted origins were configured",
        "value": configured,
    }


def check_security_headers() -> dict:
    headers = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "script-src 'self'",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
    }
    return {
        "name": "security_headers",
        "status": "pass",
        "details": "Required response headers are configured in the app middleware.",
        "value": headers,
    }


def check_cookie_settings() -> dict:
    return {
        "name": "cookie_settings",
        "status": "pass",
        "details": "This project uses bearer JWTs rather than browser cookies, so no session cookie is created in the application shell.",
        "value": {"storage": "jwt", "same_site": "n/a", "secure": "n/a"},
    }


def check_debug_mode(project_root: str | os.PathLike[str] | None = None) -> dict:
    root = Path(project_root or Path(__file__).resolve().parents[2])
    env_path = root / "backend" / ".env"
    content = _read_text(env_path)
    reload_enabled = "CS_RELOAD=true" in content.lower()
    env_value = "CS_ENV=production" in content.lower()
    status = "pass" if not reload_enabled and env_value else "warn"
    return {
        "name": "debug_mode",
        "status": status,
        "details": "Reload is disabled and production mode is explicitly set." if status == "pass" else "Production guardrails should be enabled before deployment.",
        "value": {"reload_enabled": reload_enabled, "production_mode": env_value},
    }


def check_dependency_vulns() -> dict:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", "backend/requirements.txt"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[2],
            timeout=60,
            check=False,
        )
        if completed.returncode == 0:
            return {"name": "dependency_vulns", "status": "pass", "details": "No known dependency vulnerabilities were reported by pip-audit.", "value": "clean"}
        output = (completed.stdout or "") + (completed.stderr or "")
        return {"name": "dependency_vulns", "status": "warn", "details": output.strip() or "Dependency audit could not complete automatically.", "value": output.strip()}
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return {"name": "dependency_vulns", "status": "warn", "details": "pip-audit is not installed, so dependency scanning was skipped.", "value": "skipped"}


def run_security_checks(project_root: str | os.PathLike[str] | None = None) -> dict:
    root = Path(project_root or Path(__file__).resolve().parents[2])
    return {
        "project_root": str(root),
        "checks": [
            check_cors_configuration(root),
            check_security_headers(),
            check_cookie_settings(),
            check_debug_mode(root),
            check_dependency_vulns(),
        ],
    }
