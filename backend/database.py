"""
Database configuration with PostgreSQL support and SQLite fallback.
"""
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool
import os
import tempfile


# Auto-detect best database configuration
is_serverless = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
DATABASE_URL = os.getenv("DATABASE_URL")

if is_serverless:
    # On serverless (Vercel), local relative SQLite file paths in /var/task fail because the directory is read-only.
    # Only remote PostgreSQL/MySQL or in-memory SQLite with StaticPool are supported.
    if DATABASE_URL and (DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")):
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        _is_sqlite = False
        engine_kwargs = {"echo": False}
    else:
        DATABASE_URL = "sqlite:///:memory:"
        _is_sqlite = True
        engine_kwargs = {
            "echo": False,
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        }
else:
    # Standard local desktop/server installation
    if not DATABASE_URL:
        _db_dir = os.path.dirname(os.path.abspath(__file__))
        _db_path = os.path.join(_db_dir, "cryptojacking.db")
        DATABASE_URL = f"sqlite:///{_db_path}"
    elif DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    _is_sqlite = DATABASE_URL.startswith("sqlite")
    engine_kwargs = {"echo": False}
    if _is_sqlite:
        engine_kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in DATABASE_URL:
            engine_kwargs["poolclass"] = StaticPool

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ScopedSession = scoped_session(SessionLocal)
Base = declarative_base()
_db_initialized = False


def get_db():
    """FastAPI dependency - yields a DB session"""
    global _db_initialized
    if not _db_initialized and os.getenv("VERCEL"):
        init_db()
    db = ScopedSession()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables on startup and apply lightweight compatibility migrations."""
    global _db_initialized
    from backend.models import agent_command, alert, audit_log, metric, notification_channel, report, system, user  # noqa

    print(f"Database: {DATABASE_URL}")

    Base.metadata.create_all(bind=engine)
    _apply_compat_migrations()
    _db_initialized = True
    print("All tables ready")


def _apply_compat_migrations():
    """Best-effort compatibility migrations for existing local databases."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    if "users" in existing_tables:
        _ensure_column("users", "profile_picture_url", "TEXT")
        _ensure_column("users", "password_updated_at", "DATETIME")

    if "reports" in existing_tables:
        _ensure_column("reports", "file_type", "TEXT")
        _ensure_column("reports", "size_bytes", "INTEGER")

    if "alerts" in existing_tables:
        _ensure_column("alerts", "feature_importance", "TEXT")


def _ensure_column(table_name: str, column_name: str, column_type_sql: str):
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns(table_name)}
    if column_name in columns:
        return

    with engine.begin() as connection:
        connection.execute(
            text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type_sql}")
        )
