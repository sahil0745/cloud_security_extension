import asyncio
from database.db import AsyncSessionLocal
from sqlalchemy import select
from models.models import ConfigHistory
from services.rules_engine.evaluator import RuleEvaluator

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ConfigHistory).order_by(ConfigHistory.scanned_at.desc()))
        h = result.scalars().first()
        print('Config:', h.configuration)
        res = RuleEvaluator.evaluate(h.platform, h.configuration)
        print('Violations:', res)

asyncio.run(main())
