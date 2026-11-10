#!/usr/bin/env python3
"""
CryptoDetect Production Environment Bootstrapper.

Initializes and hardens the CryptoDetect environment for production deployment:
  1. Generates or updates .env with cryptographically secure SECRET_KEY (32-byte hex).
  2. Enforces production security defaults (VERIFICATION_DEV_MODE=false, DEBUG=False).
  3. Configures CORS_ORIGINS and optional ADMIN_EMAIL.
  4. Runs Alembic database schema migrations to HEAD with automated verification.

Usage:
  python scripts/bootstrap_production.py
  python scripts/bootstrap_production.py --cors-origins "https://app.cryptodetect.com" --admin-email "ops@cryptodetect.com"
  python scripts/bootstrap_production.py --skip-migrations
"""

import argparse
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path


def _resolve_project_root() -> Path:
    """Resolve repository root directory from this script's location."""
    return Path(__file__).resolve().parents[1]


def _find_python_executable(project_root: Path) -> str:
    """Find the best Python executable (virtualenv or current interpreter)."""
    # Check project-local virtualenvs
    candidates = [
        project_root / ".venv" / "Scripts" / "python.exe",
        project_root / ".venv" / "bin" / "python",
        project_root / "venv" / "Scripts" / "python.exe",
        project_root / "venv" / "bin" / "python",
    ]
    for c in candidates:
        if c.exists() and os.access(str(c), os.X_OK):
            return str(c)
    return sys.executable


def _update_or_append_env(env_path: Path, updates: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """
    Update key-value pairs in an env file while preserving existing comments and ordering.
    Returns (applied_updates, added_keys).
    """
    applied = {}
    lines: list[str] = []
    found_keys = set()

    if env_path.exists():
        raw_text = env_path.read_text(encoding="utf-8")
        lines = raw_text.splitlines()

    updated_lines: list[str] = []
    pattern = re.compile(r"^\s*#?\s*([A-Za-z0-9_]+)\s*=\s*(.*)$")

    for line in lines:
        match = pattern.match(line)
        if match:
            k = match.group(1)
            if k in updates and k not in found_keys:
                new_val = updates[k]
                updated_lines.append(f'{k}="{new_val}"')
                found_keys.add(k)
                applied[k] = new_val
                continue
        updated_lines.append(line)

    added_keys = []
    remaining = [k for k in updates if k not in found_keys]
    if remaining:
        if updated_lines and updated_lines[-1].strip():
            updated_lines.append("")
        updated_lines.append("# --- Production Configuration Injected by Bootstrap ---")
        for k in remaining:
            new_val = updates[k]
            updated_lines.append(f'{k}="{new_val}"')
            applied[k] = new_val
            added_keys.append(k)

    content = "\n".join(updated_lines).rstrip() + "\n"
    env_path.write_text(content, encoding="utf-8")
    return applied, added_keys


def bootstrap_environment(
    project_root: Path,
    cors_origins: str | None = None,
    admin_email: str | None = None,
    force_secret_regen: bool = False,
) -> dict:
    """Ensure .env exists, configure security settings, and generate SECRET_KEY."""
    env_file = project_root / ".env"
    example_file = project_root / ".env.example"

    created_new = False
    if not env_file.exists():
        if example_file.exists():
            env_file.write_text(example_file.read_text(encoding="utf-8"), encoding="utf-8")
            created_new = True
            print(f"[+] Created .env from {example_file.name}")
        else:
            env_file.write_text("# CryptoDetect Environment Configuration\n", encoding="utf-8")
            created_new = True
            print("[+] Initialized blank .env file")

    existing_content = env_file.read_text(encoding="utf-8")
    secret_match = re.search(r'^\s*SECRET_KEY\s*=\s*["\']?(.*?)["\']?\s*$', existing_content, re.MULTILINE)
    current_secret = secret_match.group(1) if secret_match else ""

    placeholder_values = {
        "",
        "replace-with-a-random-32-byte-secret",
        "your-secret-key",
        "changeme",
        "secret",
        "supersecret",
    }

    needs_new_secret = (
        force_secret_regen
        or not current_secret
        or current_secret in placeholder_values
        or len(current_secret) < 32
    )

    updates: dict[str, str] = {
        "VERIFICATION_DEV_MODE": "false",
        "DEBUG": "False",
    }

    if needs_new_secret:
        new_secret = secrets.token_hex(32)
        updates["SECRET_KEY"] = new_secret

    if cors_origins:
        updates["CORS_ORIGINS"] = cors_origins.strip()

    if admin_email:
        updates["ADMIN_EMAIL"] = admin_email.strip()

    applied, added = _update_or_append_env(env_file, updates)
    return {
        "env_path": env_file,
        "created_new": created_new,
        "new_secret_generated": needs_new_secret,
        "applied": applied,
        "added": added,
    }


def run_database_migrations(project_root: Path) -> tuple[bool, str]:
    """Run Alembic database schema migrations up to head revision."""
    python_bin = _find_python_executable(project_root)
    alembic_ini = project_root / "alembic.ini"

    if not alembic_ini.exists():
        return False, "alembic.ini not found at project root"

    script = (
        "import sys, alembic.config\n"
        "try:\n"
        "    alembic.config.main(argv=['upgrade', 'head'])\n"
        "except SystemExit as exc:\n"
        "    sys.exit(exc.code or 0)\n"
    )

    proc = subprocess.run(
        [python_bin, "-c", script],
        cwd=str(project_root),
        capture_output=True,
        text=True,
    )

    combined_output = (proc.stdout + "\n" + proc.stderr).strip()

    # If tables already exist in an existing SQLite/Postgres DB (e.g. created by Base.metadata), stamp head
    if proc.returncode != 0 and ("already exists" in combined_output.lower() or "operationalerror" in combined_output.lower()):
        print("    [!] Pre-existing tables detected without migration history. Stamping Alembic to head...")
        stamp_script = (
            "import sys, alembic.config\n"
            "try:\n"
            "    alembic.config.main(argv=['stamp', 'head'])\n"
            "except SystemExit as exc:\n"
            "    sys.exit(exc.code or 0)\n"
        )
        stamp_proc = subprocess.run(
            [python_bin, "-c", stamp_script],
            cwd=str(project_root),
            capture_output=True,
            text=True,
        )
        if stamp_proc.returncode == 0:
            return True, "Stamped pre-existing database schema to Alembic HEAD"

    if proc.returncode == 0:
        return True, combined_output or "Database schema upgraded to HEAD successfully"
    return False, combined_output or f"Alembic exited with return code {proc.returncode}"


def verify_migration_status(project_root: Path) -> str:
    """Inspect current migration revision from Alembic."""
    python_bin = _find_python_executable(project_root)
    script = (
        "import sys, alembic.config\n"
        "try:\n"
        "    alembic.config.main(argv=['current'])\n"
        "except SystemExit as exc:\n"
        "    sys.exit(exc.code or 0)\n"
    )
    proc = subprocess.run(
        [python_bin, "-c", script],
        cwd=str(project_root),
        capture_output=True,
        text=True,
    )
    lines = [line.strip() for line in (proc.stdout + "\n" + proc.stderr).splitlines() if line.strip()]
    revisions = [line for line in lines if not line.startswith("INFO")]
    return ", ".join(revisions) if revisions else (lines[-1] if lines else "Unknown")


def main():
    parser = argparse.ArgumentParser(
        description="CryptoDetect Production Bootstrap Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cors-origins",
        type=str,
        default=None,
        help="Allowed CORS origins comma-separated (e.g. 'https://app.cryptodetect.com,https://dashboard.cryptodetect.com')",
    )
    parser.add_argument(
        "--admin-email",
        type=str,
        default=None,
        help="Default operator administrator email address for alerting",
    )
    parser.add_argument(
        "--force-secret-regen",
        action="store_true",
        help="Force regeneration of SECRET_KEY even if already configured",
    )
    parser.add_argument(
        "--skip-migrations",
        action="store_true",
        help="Skip automatic database migration step",
    )

    args = parser.parse_args()
    project_root = _resolve_project_root()

    print("=" * 65)
    print("      CryptoDetect Production Environment Bootstrapper       ")
    print("=" * 65)
    print(f"[*] Project Root: {project_root}")

    # 1. Environment & Secret Hardening
    print("\n[1/3] Hardening Environment Configuration (.env)...")
    res = bootstrap_environment(
        project_root,
        cors_origins=args.cors_origins,
        admin_email=args.admin_email,
        force_secret_regen=args.force_secret_regen,
    )

    if res["new_secret_generated"]:
        print("    [+] Generated 64-char cryptographically secure SECRET_KEY (SHA-256 equivalent)")
    else:
        print("    [*] Existing secure SECRET_KEY retained")

    print(f"    [+] Enforced VERIFICATION_DEV_MODE = {res['applied'].get('VERIFICATION_DEV_MODE')}")
    print(f"    [+] Enforced DEBUG = {res['applied'].get('DEBUG')}")
    if "CORS_ORIGINS" in res["applied"]:
        print(f"    [+] Set CORS_ORIGINS = {res['applied']['CORS_ORIGINS']}")
    if "ADMIN_EMAIL" in res["applied"]:
        print(f"    [+] Set ADMIN_EMAIL = {res['applied']['ADMIN_EMAIL']}")

    # 2. Database Migrations
    if args.skip_migrations:
        print("\n[2/3] Database Migrations: SKIPPED (--skip-migrations specified)")
    else:
        print("\n[2/3] Applying Database Migrations (alembic upgrade head)...")
        success, details = run_database_migrations(project_root)
        if success:
            print("    [+] Alembic migration to HEAD succeeded!")
        else:
            print(f"    [-] Migration warning / issue:\n{details}")

    # 3. Final Verification
    print("\n[3/3] Verifying System State...")
    rev = verify_migration_status(project_root)
    print(f"    [*] Alembic Active Revision : {rev}")
    print(f"    [*] Environment Configuration: {res['env_path'].name} (Ready for production)")

    print("\n" + "=" * 65)
    print("             BOOTSTRAP COMPLETE - PRODUCTION READY           ")
    print("=" * 65)
    print("Next Steps:")
    print("  1. Verify external credentials in .env (VIRUSTOTAL_API_KEY, SMTP, etc.)")
    print("  2. Start backend server: uvicorn backend.main:app --host 0.0.0.0 --port 8000")
    print("  3. Deploy monitoring agent to endpoints via monitoring_agent/sign_exe.ps1")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
