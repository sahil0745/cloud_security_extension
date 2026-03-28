from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import os
import uuid
from database.db import get_db
from models.models import User
from auth.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    timedelta,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_MINUTES,
)
from pydantic import BaseModel, Field
from services.redis_cache import redis_cache, get_redis
from services.rate_limiter import create_rate_limiter

# Allow short retry bursts while still throttling brute-force attempts.
login_rate_limit = create_rate_limiter(5, 60, "login")

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    role: str = "USER"
    admin_bootstrap_token: str = ""

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register")
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    requested_role = user.role.upper()
    if requested_role not in {"USER", "ADMIN"}:
        raise HTTPException(status_code=400, detail="Invalid role requested")

    if requested_role == "ADMIN":
        expected_token = os.getenv("ADMIN_BOOTSTRAP_TOKEN", "")
        if not expected_token or user.admin_bootstrap_token != expected_token:
            raise HTTPException(status_code=403, detail="Admin registration is forbidden")

    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalars().first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password, role=requested_role)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "User registered successfully", "username": new_user.username}

@router.post("/login", dependencies=[Depends(login_rate_limit)])
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == form_data.username))
    user = result.scalars().first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    session_id = str(uuid.uuid4())
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "sid": session_id}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": user.username, "role": user.role, "sid": session_id},
        expires_delta=timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES),
    )

    await redis_cache.cache_session(session_id, {"username": user.username, "role": user.role}, ttl=3600)

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh")
async def refresh_access_token(token_data: dict = Depends(verify_refresh_token)):
    session = await redis_cache.get_session(token_data["sid"])
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    access_token = create_access_token(
        data={"sub": token_data["username"], "role": token_data["role"], "sid": token_data["sid"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(
        data={"sub": token_data["username"], "role": token_data["role"], "sid": token_data["sid"]},
        expires_delta=timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES),
    )

    await redis_cache.cache_session(token_data["sid"], {"username": token_data["username"], "role": token_data["role"]}, ttl=3600)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
