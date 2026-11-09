"""Add audit_logs, notification_channels, agent_commands, and alert feature_importance.

Revision ID: 0002_containment_and_audit
Revises: 0001_initial_schema
Create Date: 2026-11-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_containment_and_audit"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "alerts" in existing_tables:
        alert_cols = {c["name"] for c in inspector.get_columns("alerts")}
        if "feature_importance" not in alert_cols:
            op.add_column("alerts", sa.Column("feature_importance", sa.JSON(), nullable=True))

    if "audit_logs" not in existing_tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("actor_email", sa.String(), nullable=False),
            sa.Column("action", sa.String(), nullable=False),
            sa.Column("target_type", sa.String(), nullable=True),
            sa.Column("target_id", sa.String(), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("ip_address", sa.String(), nullable=True),
            sa.Column("timestamp", sa.DateTime(), nullable=True),
        )
        op.create_index(op.f("ix_audit_logs_actor_email"), "audit_logs", ["actor_email"], unique=False)
        op.create_index(op.f("ix_audit_logs_timestamp"), "audit_logs", ["timestamp"], unique=False)
        op.create_index("idx_audit_actor_action", "audit_logs", ["actor_email", "action"], unique=False)
        op.create_index("idx_audit_timestamp", "audit_logs", ["timestamp"], unique=False)

    if "notification_channels" not in existing_tables:
        op.create_table(
            "notification_channels",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_email", sa.String(), sa.ForeignKey("users.email"), nullable=False),
            sa.Column("channel_type", sa.String(), nullable=False),
            sa.Column("target", sa.String(), nullable=False),
            sa.Column("verified", sa.Boolean(), nullable=True, server_default=sa.text("0")),
            sa.Column("verify_code", sa.String(), nullable=True),
            sa.Column("code_expires", sa.DateTime(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=True, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(), nullable=True),
        )
        op.create_index(op.f("ix_notification_channels_user_email"), "notification_channels", ["user_email"], unique=False)
        op.create_index("idx_notif_user_type", "notification_channels", ["user_email", "channel_type"], unique=False)

    if "agent_commands" not in existing_tables:
        op.create_table(
            "agent_commands",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("system_id", sa.String(), sa.ForeignKey("monitored_systems.system_id"), nullable=False),
            sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
            sa.Column("action", sa.String(), nullable=False),
            sa.Column("target_payload", sa.JSON(), nullable=True),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("requested_by", sa.String(), nullable=False),
            sa.Column("result_data", sa.JSON(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
        )
        op.create_index(op.f("ix_agent_commands_system_id"), "agent_commands", ["system_id"], unique=False)
        op.create_index(op.f("ix_agent_commands_alert_id"), "agent_commands", ["alert_id"], unique=False)
        op.create_index(op.f("ix_agent_commands_status"), "agent_commands", ["status"], unique=False)
        op.create_index("idx_agent_cmd_sys_status", "agent_commands", ["system_id", "status"], unique=False)
        op.create_index("idx_agent_cmd_alert", "agent_commands", ["alert_id"], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "agent_commands" in existing_tables:
        op.drop_table("agent_commands")

    if "notification_channels" in existing_tables:
        op.drop_table("notification_channels")

    if "audit_logs" in existing_tables:
        op.drop_table("audit_logs")

