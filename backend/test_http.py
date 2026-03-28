import httpx
import jwt
import asyncio
from datetime import datetime, timedelta
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def test_api():
    from auth.security import SECRET_KEY, ALGORITHM
    token = jwt.encode(
        {"sub": "admin", "username": "admin", "role": "ADMIN", "exp": datetime.utcnow() + timedelta(hours=1)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        res = await client.get("http://127.0.0.1:8001/api/export?format=pdf&use_signed_url=true", headers=headers)
        print("Status code:", res.status_code)
        print("Response:", res.text[:200])

if __name__ == "__main__":
    asyncio.run(test_api())
