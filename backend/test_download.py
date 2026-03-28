import httpx
import jwt
import asyncio
from datetime import datetime, timedelta
import os
import sys
import json

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
        data = res.json()
        print("Export Response:", data)
        download_url = "http://127.0.0.1:8001" + data["download_url"]
        
        # Now try to download it
        res2 = await client.get(download_url, headers=headers)
        print("Download Status:", res2.status_code)
        if res2.status_code != 200:
            print(res2.text)
        else:
            print(f"Downloaded {len(res2.content)} bytes")

if __name__ == "__main__":
    asyncio.run(test_api())
