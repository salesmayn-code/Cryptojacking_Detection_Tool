"""
Database configuration with PostgreSQL support and SQLite fallback.
"""
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
import os


_db_dir = os.path.dirname(os.path.abspath(__file__))
_db_path = os.path.join(_db_dir, "cryptojacking.db")
_default_sqlite_url = f"sqlite:///{_db_path}"

DATABASE_URL = os.getenv("DATABASE_URL", _default_sqlite_url)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

_is_sqlite = DATABASE_URL.startswith("sqlite")

engine_kwargs = {"echo": False}
if _is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ScopedSession = scoped_session(SessionLocal)
Base = declarative_base()


def get_db():
    """FastAPI dependency - yields a DB session"""
    db = ScopedSession()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables on startup and apply lightweight compatibility migrations."""
    from backend.models import alert, metric, report, system, user  # noqa

    if _is_sqlite:
        print(f"Database: {_db_path}")
    else:
        print(f"Database: {DATABASE_URL}")

    Base.metadata.create_all(bind=engine)
    _apply_compat_migrations()
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
