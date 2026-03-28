"""
Auto-initialization for the CloudSec Copilot database.
Runs on every server startup. Only seeds data if the database is empty.
This ensures previous records are always preserved.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func
from database.db import AsyncSessionLocal
from models.models import User, AuditLog, RiskHistory, ConfigHistory, Baseline
from auth.security import get_password_hash
import structlog

logger = structlog.get_logger()


async def init_database():
    """Initialize the database with seed data if empty. Preserves existing data."""
    async with AsyncSessionLocal() as db:
        # ── 1. Ensure admin user exists ──
        result = await db.execute(select(User).filter(User.username == "admin"))
        admin = result.scalars().first()
        if not admin:
            admin = User(
                username="admin",
                hashed_password=get_password_hash("admin12345678"),
                role="ADMIN",
            )
            db.add(admin)
            await db.commit()
            await db.refresh(admin)
            logger.info("db_init_admin_created", user_id=admin.id)
        else:
            logger.info("db_init_admin_exists", user_id=admin.id)

        user_id = admin.id

        # ── 2. Seed RiskHistory if empty (24h trend data) ──
        risk_count = (await db.execute(select(func.count()).select_from(RiskHistory))).scalar()
        if risk_count == 0:
            now = datetime.now(timezone.utc)
            for i in range(24, 0, -1):
                t = now - timedelta(hours=i)
                score = 45 + (i % 5) * 4 - (i % 3) * 2
                db.add(RiskHistory(score=score, vulnerabilities_count=score // 10, timestamp=t, user_id=user_id))
            await db.commit()
            logger.info("db_init_risk_history_seeded", count=24)
        else:
            logger.info("db_init_risk_history_exists", count=risk_count)

        # ── 3. Seed AuditLog if empty (attack vector data — platform-specific) ──
        audit_count = (await db.execute(select(func.count()).select_from(AuditLog))).scalar()
        if audit_count == 0:
            now = datetime.now(timezone.utc)
            # AWS-specific actions (s3_, iam_, ec2_, public_s3 prefixes)
            aws_actions = [
                "s3_public_access_grant", "s3_bucket_policy_change", "s3_object_acl_update",
                "iam_policy_wildcard_attach", "iam_role_escalation", "iam_user_mfa_disable",
                "ec2_security_group_open", "public_s3_bucket_created",
            ]
            # Azure-specific actions (nsg_, rbac_, network_, blob_ prefixes)
            azure_actions = [
                "nsg_rule_allow_all_inbound", "nsg_rdp_port_exposed", "nsg_ssh_open_internet",
                "rbac_owner_role_assigned", "rbac_contributor_escalation",
                "network_vnet_peering_misconfigured", "blob_public_container_created",
            ]
            # GCP-specific actions (gcs_, firewall_, compute_, privilege_ prefixes)
            gcp_actions = [
                "gcs_bucket_public_access", "gcs_object_acl_override",
                "firewall_rule_allow_all", "firewall_ingress_0000",
                "compute_instance_external_ip", "privilege_escalation_detected",
            ]

            all_actions = []
            for action in aws_actions:
                all_actions.append((action, "AWS"))
            for action in azure_actions:
                all_actions.append((action, "Azure"))
            for action in gcp_actions:
                all_actions.append((action, "GCP"))

            for i, (action, platform_label) in enumerate(all_actions):
                t = now - timedelta(hours=i)
                db.add(AuditLog(
                    user_id=user_id, action=action, resource=f"{platform_label.lower()}-resource-{i}",
                    status="failed" if "attempt" in action or "escalation" in action else "success",
                    timestamp=t,
                ))
            await db.commit()
            logger.info("db_init_audit_logs_seeded", count=len(all_actions))
        else:
            logger.info("db_init_audit_logs_exist", count=audit_count)

        # ── 4. Seed ConfigHistory if empty (violations / severity / heatmap) ──
        config_count = (await db.execute(select(func.count()).select_from(ConfigHistory))).scalar()
        if config_count == 0:
            # Get or create baseline
            result = await db.execute(select(Baseline).limit(1))
            baseline = result.scalars().first()
            if not baseline:
                baseline = Baseline(platform="AWS", account_id="demo-account", configuration={}, version=1)
                db.add(baseline)
                await db.flush()

            now = datetime.now(timezone.utc)

            # AWS config with violations
            aws_config = {
                "s3_buckets": {"prod-data-bucket": {"public_access_block": False}, "dev-assets": {"public_access_block": True}},
                "iam_policies": {"admin-policy-1": {"permissions": ["*"]}},
                "iam_users": {"service_user": {"mfa_enabled": False, "access_key_age_days": 120}},
                "security_groups": {"sg-web": {"open_ports": ["0.0.0.0/0"]}},
                "databases": {"main-db": {"publicly_accessible": True, "encrypted": False}},
            }

            # Azure config with violations
            azure_config = {
                "storage_accounts": {"prodblob01": {"public_blob_access": True}},
                "iam_policies": {"global-admin": {"permissions": ["*"]}},
                "security_groups": {"nsg-default": {"open_ports": ["0.0.0.0/0"]}},
                "databases": {"azure-sql-main": {"publicly_accessible": True, "encrypted": False}},
            }

            # GCP config with violations
            gcp_config = {
                "cloud_storage": {"gcp-public-bucket": {"public_access": True}},
                "iam_policies": {"gcp-admin-policy": {"permissions": ["*"]}},
                "security_groups": {"fw-open": {"open_ports": ["0.0.0.0/0"]}},
                "databases": {"gcp-cloud-sql": {"publicly_accessible": True, "encrypted": False}},
            }

            for i, (platform, config) in enumerate([("AWS", aws_config), ("Azure", azure_config), ("GCP", gcp_config)]):
                db.add(ConfigHistory(
                    baseline_id=baseline.id, platform=platform, configuration=config,
                    drift_detected=[{"field": "root", "old": None, "new": config, "type": "added"}],
                    scanned_at=now - timedelta(minutes=i * 2),
                ))
            await db.commit()
            logger.info("db_init_config_history_seeded", platforms=["AWS", "Azure", "GCP"])
        else:
            logger.info("db_init_config_history_exists", count=config_count)

    logger.info("db_init_complete", msg="Database initialization finished. Previous records preserved.")
