"""Initial schema for CryptoDetect.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-04-25
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False, unique=True),
        sa.Column("full_name", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("system_id", sa.String(), nullable=False, unique=True),
        sa.Column("api_key", sa.String(), nullable=False, unique=True),
        sa.Column("role", sa.String(), nullable=False, server_default="user"),
        sa.Column("profile_picture_url", sa.String(), nullable=True),
        sa.Column("password_updated_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_system_id"), "users", ["system_id"], unique=True)
    op.create_index(op.f("ix_users_api_key"), "users", ["api_key"], unique=True)

    op.create_table(
        "monitored_systems",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("system_id", sa.String(), nullable=False, unique=True),
        sa.Column("system_name", sa.String(), nullable=False),
        sa.Column("system_description", sa.Text(), nullable=True),
        sa.Column("owner_email", sa.String(), sa.ForeignKey("users.email"), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="offline"),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("device_info", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_monitored_systems_system_id"), "monitored_systems", ["system_id"], unique=True)

    op.create_table(
        "system_metrics",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("system_id", sa.String(), sa.ForeignKey("monitored_systems.system_id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=True),
        sa.Column("memory_percent", sa.Float(), nullable=True),
        sa.Column("network_bytes_sent", sa.Integer(), nullable=True),
        sa.Column("network_bytes_recv", sa.Integer(), nullable=True),
        sa.Column("processes_data", sa.JSON(), nullable=True),
        sa.Column("raw_metrics", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("idx_metric_system_time"), "system_metrics", ["system_id", "timestamp"], unique=False)

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("system_id", sa.String(), sa.ForeignKey("monitored_systems.system_id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("alert_type", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detection_method", sa.String(), nullable=True, server_default="heuristic"),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("suspicious_processes", sa.JSON(), nullable=True),
        sa.Column("virustotal_results", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="unread"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("idx_alert_system_status"), "alerts", ["system_id", "status"], unique=False)
    op.create_index(op.f("idx_alert_timestamp"), "alerts", ["timestamp"], unique=False)

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("system_id", sa.String(), sa.ForeignKey("monitored_systems.system_id"), nullable=False),
        sa.Column("owner_email", sa.String(), nullable=False),
        sa.Column("start_date", sa.DateTime(), nullable=False),
        sa.Column("end_date", sa.DateTime(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("format", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="completed"),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("file_type", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("idx_report_system_created"), "reports", ["system_id", "created_at"], unique=False)


def downgrade():
    op.drop_index(op.f("idx_report_system_created"), table_name="reports")
    op.drop_table("reports")

    op.drop_index(op.f("idx_alert_timestamp"), table_name="alerts")
    op.drop_index(op.f("idx_alert_system_status"), table_name="alerts")
    op.drop_table("alerts")

    op.drop_index(op.f("idx_metric_system_time"), table_name="system_metrics")
    op.drop_table("system_metrics")

    op.drop_index(op.f("ix_monitored_systems_system_id"), table_name="monitored_systems")
    op.drop_table("monitored_systems")

    op.drop_index(op.f("ix_users_api_key"), table_name="users")
    op.drop_index(op.f("ix_users_system_id"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
