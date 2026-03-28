"""Quick check: what does the latest config row for each platform look like?"""
import asyncio, os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv; load_dotenv()
from database.db import AsyncSessionLocal
from sqlalchemy import select, func
from models.models import ConfigHistory
from services.rules_engine.evaluator import RuleEvaluator

async def main():
    async with AsyncSessionLocal() as db:
        total = (await db.execute(select(func.count()).select_from(ConfigHistory))).scalar()
        print(f"Total ConfigHistory rows: {total}")
        
        for platform in ["AWS", "Azure", "GCP"]:
            result = await db.execute(
                select(ConfigHistory)
                .where(ConfigHistory.platform == platform)
                .order_by(ConfigHistory.scanned_at.desc())
                .limit(1)
            )
            row = result.scalars().first()
            if not row:
                print(f"\n{platform}: NO ROWS")
                continue
            config = row.configuration
            is_dict = isinstance(config, dict)
            keys = list(config.keys()) if is_dict else "N/A"
            has_sg = "security_groups" in config if is_dict else False
            has_db = "databases" in config if is_dict else False
            has_iam = "iam_policies" in config if is_dict else False
            sg_val = config.get("security_groups", {}) if is_dict else {}
            
            # Evaluate violations
            viols = 0
            viol_details = []
            if is_dict:
                r = RuleEvaluator.evaluate(platform, config)
                violations = r.get("violations", [])
                viols = len(violations)
                viol_details = [(v["rule_id"], v["severity"]) for v in violations]
            
            print(f"\n{platform}: keys={keys}")
            print(f"  has_sg={has_sg} has_db={has_db} has_iam={has_iam}")
            print(f"  security_groups content: {json.dumps(sg_val)}")
            print(f"  violations: {viols} -> {viol_details}")

asyncio.run(main())
