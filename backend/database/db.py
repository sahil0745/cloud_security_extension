import os
from dotenv import load_dotenv
load_dotenv()
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

# Fallback to aiosqlite locally, but strictly default to PostgreSQL for Production
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost/cloudsec")
ENVIRONMENT = os.getenv("ENV", "DEV")

if DATABASE_URL.startswith("sqlite"):
    if ENVIRONMENT == "PROD":
        raise RuntimeError("SQLite is not allowed in PROD. Configure PostgreSQL with asyncpg.")
    if DATABASE_URL.startswith("sqlite://") and not DATABASE_URL.startswith("sqlite+aiosqlite://"):
        DATABASE_URL = DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://")

connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine_kwargs = {
    "connect_args": connect_args,
    "pool_pre_ping": True,
}
if "sqlite" not in DATABASE_URL:
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "20")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "40")),
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "1800")),
    })

engine = create_async_engine(DATABASE_URL, **engine_kwargs)
AsyncSessionLocal = async_sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=AsyncSession)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
