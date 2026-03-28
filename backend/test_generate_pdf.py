import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.db import AsyncSessionLocal
from services.reporting.report_generator import report_generator

async def test_pdf():
    async with AsyncSessionLocal() as db:
        try:
            pdf_bytes = await report_generator.generate_pdf_report_async(db)
            print(f"Success PDF generated: {len(pdf_bytes)} bytes")
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_pdf())
