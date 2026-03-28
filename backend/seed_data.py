import asyncio
import os
import sys

# Ensure backend directory is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from database.db import AsyncSessionLocal
from models.models import User, AuditLog, RiskHistory, ConfigHistory, Baseline
from sqlalchemy import select

async def seed_data():
    async with AsyncSessionLocal() as db:
        # Check if we already seeded RiskHistory recently to prevent duplicating rows unnecessarily
        result = await db.execute(select(RiskHistory).limit(1))
        if result.scalars().first():
            print("RiskHistory already has data. We will add more just in case.")

        # Get admin user
        result = await db.execute(select(User).filter(User.username == "admin"))
        user = result.scalars().first()
        user_id = user.id if user else None

        now = datetime.now(timezone.utc)
        print("Seeding RiskHistory...")
        for i in range(24, 0, -1):
            t = now - timedelta(hours=i)
            # Make risk fluctuate a bit between 40 and 60
            score = 45 + (i % 5) * 4 - (i % 3) * 2
            vulns = score // 10
            
            risk = RiskHistory(
                score=score,
                vulnerabilities_count=vulns,
                timestamp=t,
                user_id=user_id
            )
            db.add(risk)
        
        print("Seeding AuditLog for Attack Vectors...")
        actions = [
            "policy_delete_attempt", "policy_delete_attempt", "policy_delete_attempt", 
            "iam_policy_change", "iam_policy_change", "iam_role_escalation", 
            "public_s3_bucket_created", "security_group_open", "privilege_escalation"
        ]
        for i, action in enumerate(actions):
            t = now - timedelta(hours=i*2)
            log = AuditLog(
                user_id=user_id,
                action=action,
                resource=f"resource-{i}",
                status="failed" if "attempt" in action else "success",
                timestamp=t
            )
            db.add(log)
            
        print("Seeding ConfigHistory for Severity Distribution and Heatmap...")
        config = {
            "s3_buckets": {
                "prod-data-bucket": {"public_access_block": False}, # S3_PUBLIC_ACCESS violation -> HIGH
                "dev-assets": {"public_access_block": True}
            },
            "iam_policies": {
                "admin-policy-1": {"permissions": ["*"]}, # IAM_WILDCARD_PERMISSIONS violation -> CRITICAL
            },
            "iam_users": {
                "service_user": {"mfa_enabled": False, "access_key_age_days": 120} # IAM_NO_MFA and IAM_STALE_CREDENTIALS -> MEDIUM
            },
            "security_groups": {
                "sg-web": {"open_ports": ["0.0.0.0/0"]}, # NETWORK_OPEN_PORTS -> CRITICAL
            },
            "databases": {
                "main-db": {"publicly_accessible": True, "encrypted": False} # NETWORK_EXPOSED_DB and DB_NO_ENCRYPTION -> HIGH/MEDIUM
            }
        }
        
        # Add a fake baseline
        baseline = Baseline(platform="AWS", account_id="demo-account", configuration=config, version=1)
        db.add(baseline)
        await db.flush() 
        
        history = ConfigHistory(
            baseline_id=baseline.id,
            platform="AWS",
            configuration=config,
            drift_detected=[{"field": "root", "old": None, "new": config, "type": "added"}],
            scanned_at=now
        )
        db.add(history)
        
        history_gcp = ConfigHistory(
            baseline_id=baseline.id,
            platform="GCP",
            configuration=config,
            scanned_at=now - timedelta(minutes=5)
        )
        db.add(history_gcp)

        history_azure = ConfigHistory(
            baseline_id=baseline.id,
            platform="Azure",
            configuration=config,
            scanned_at=now - timedelta(minutes=10)
        )
        db.add(history_azure)
        
        await db.commit()
        print("Done seeding demo data! Refresh your dashboard on the frontend.")

if __name__ == "__main__":
    asyncio.run(seed_data())
