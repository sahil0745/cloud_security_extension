import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database.db import AsyncSessionLocal, engine, Base
from models.models import User
from auth.security import get_password_hash
from sqlalchemy import select

async def main():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).filter(User.username == "admin"))
        existing = result.scalars().first()
        if existing:
            print(f"Admin already exists with id={existing.id}")
            return
        
        user = User(
            username="admin",
            hashed_password=get_password_hash("admin12345678"),
            role="ADMIN"
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        print(f"Admin user created with id={user.id}")

asyncio.run(main())
