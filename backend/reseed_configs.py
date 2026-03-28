"""Clear old config history and re-seed with fresh violation-triggering data."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime, timedelta, timezone
from database.db import AsyncSessionLocal, engine, Base
from models.models import ConfigHistory, Baseline
from sqlalchemy import delete, select

async def main():
    async with AsyncSessionLocal() as db:
        # Clear ALL old ConfigHistory
        await db.execute(delete(ConfigHistory))
        await db.commit()
        print("Cleared all ConfigHistory rows.")
        
        # Get or create baseline
        result = await db.execute(select(Baseline).limit(1))
        baseline = result.scalars().first()
        if not baseline:
            baseline = Baseline(platform="AWS", account_id="demo-account", configuration={}, version=1)
            db.add(baseline)
            await db.flush()
        
        now = datetime.now(timezone.utc)
        
        # AWS config that triggers violations
        aws_config = {
            "s3_buckets": {
                "prod-data-bucket": {"public_access_block": False},
                "dev-assets": {"public_access_block": True}
            },
            "iam_policies": {
                "admin-policy-1": {"permissions": ["*"]},
            },
            "iam_users": {
                "service_user": {"mfa_enabled": False, "access_key_age_days": 120}
            },
            "security_groups": {
                "sg-web": {"open_ports": ["0.0.0.0/0"]},
            },
            "databases": {
                "main-db": {"publicly_accessible": True, "encrypted": False}
            }
        }
        
        # Azure config that also triggers violations  
        azure_config = {
            "storage_accounts": {
                "prodblob01": {"public_blob_access": True}
            },
            "s3_buckets": {},
            "iam_policies": {
                "global-admin": {"permissions": ["*"]}
            },
            "security_groups": {
                "nsg-default": {"open_ports": ["0.0.0.0/0"]}
            },
            "databases": {
                "azure-sql-main": {"publicly_accessible": True, "encrypted": False}
            }
        }
        
        # GCP config that also triggers violations
        gcp_config = {
            "cloud_storage": {
                "gcp-public-bucket": {"public_access": True}
            },
            "iam_policies": {
                "gcp-admin-policy": {"permissions": ["*"]}
            },
            "security_groups": {
                "fw-open": {"open_ports": ["0.0.0.0/0"]}
            },
            "databases": {
                "gcp-cloud-sql": {"publicly_accessible": True, "encrypted": False}
            }
        }
        
        # Insert all three as recent scans
        for i, (platform, config) in enumerate([
            ("AWS", aws_config),
            ("Azure", azure_config),
            ("GCP", gcp_config),
        ]):
            history = ConfigHistory(
                baseline_id=baseline.id,
                platform=platform,
                configuration=config,
                drift_detected=[{"field": "root", "old": None, "new": config, "type": "added"}],
                scanned_at=now - timedelta(minutes=i * 2)
            )
            db.add(history)
        
        await db.commit()
        print("Re-seeded 3 ConfigHistory rows (AWS, Azure, GCP) with violation-triggering data.")
        
        # Verify
        from services.rules_engine.evaluator import RuleEvaluator
        for platform, config in [("AWS", aws_config), ("Azure", azure_config), ("GCP", gcp_config)]:
            res = RuleEvaluator.evaluate(platform, config)
            print(f"  {platform}: {len(res.get('violations', []))} violations, risk_score={res.get('risk_score')}")

asyncio.run(main())
