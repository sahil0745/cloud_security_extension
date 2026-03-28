"""Diagnostic: check what key the seed used vs what the server uses."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

from services.encryption import _ENCRYPTION_KEYS, DBEncryption

print(f"AES_ENCRYPTION_KEY env: {os.getenv('AES_ENCRYPTION_KEY', 'NOT SET')[:20]}...")
print(f"Number of loaded keys: {len(_ENCRYPTION_KEYS)}")

import asyncio
from database.db import AsyncSessionLocal
from sqlalchemy import select
from models.models import ConfigHistory

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ConfigHistory).order_by(ConfigHistory.scanned_at.desc()))
        h = result.scalars().first()
        if not h:
            print("NO ConfigHistory found!")
            return
        
        print(f"Platform: {h.platform}")
        config = h.configuration
        print(f"Config type: {type(config)}")
        print(f"Config is dict: {isinstance(config, dict)}")
        if isinstance(config, dict):
            print(f"Config keys: {list(config.keys())}")
            # Now evaluate
            from services.rules_engine.evaluator import RuleEvaluator
            res = RuleEvaluator.evaluate(h.platform, config)
            print(f"Violations count: {len(res.get('violations', []))}")
            print(f"Risk score: {res.get('risk_score')}")
            for v in res.get('violations', []):
                print(f"  - {v['rule_id']}: {v['severity']} - {v.get('resource', 'N/A')}")
        else:
            print(f"Config value (first 100 chars): {str(config)[:100]}")
            print("ERROR: Config did not decrypt to dict!")

asyncio.run(main())
