import sys
import os
import asyncio
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.db import AsyncSessionLocal
from routes.api import export_pdf

async def test_export():
    async with AsyncSessionLocal() as db:
        try:
            res = await export_pdf(
                severity=None,
                start_time=None,
                end_time=None,
                compliance_mode=False,
                compliance_standard="SOC2",
                scope="global",
                tenant_id=None,
                use_signed_url=False,
                current_user={"username": "admin", "role": "ADMIN"},
                db=db
            )
            print("Direct Response:", type(res), getattr(res, "status_code", "unknown"))

            res2 = await export_pdf(
                severity=None,
                start_time=None,
                end_time=None,
                compliance_mode=False,
                compliance_standard="SOC2",
                scope="global",
                tenant_id=None,
                use_signed_url=True,
                current_user={"username": "admin", "role": "ADMIN"},
                db=db
            )
            print("Signed Response:", res2)

        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_export())
