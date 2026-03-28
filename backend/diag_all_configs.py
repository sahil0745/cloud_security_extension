"""Check all ConfigHistory rows and evaluate each one."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

from database.db import AsyncSessionLocal
from sqlalchemy import select
from models.models import ConfigHistory
from services.rules_engine.evaluator import RuleEvaluator

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ConfigHistory).order_by(ConfigHistory.scanned_at.desc()).limit(10))
        rows = list(result.scalars().all())
        print(f"Total ConfigHistory rows: {len(rows)}")
        
        for i, h in enumerate(rows):
            config = h.configuration
            is_dict = isinstance(config, dict)
            print(f"\n--- Row {i} ---")
            print(f"  Platform: {h.platform}")
            print(f"  Scanned: {h.scanned_at}")
            print(f"  Config type: {type(config).__name__}")
            print(f"  Is dict: {is_dict}")
            if is_dict:
                print(f"  Config keys: {list(config.keys())}")
                res = RuleEvaluator.evaluate(h.platform, config)
                violations = res.get('violations', [])
                print(f"  Violations: {len(violations)}")
                for v in violations:
                    print(f"    - {v['rule_id']}: {v['severity']} ({v.get('resource', 'N/A')})")
            else:
                print(f"  Config (first 80 chars): {str(config)[:80]}")

asyncio.run(main())
