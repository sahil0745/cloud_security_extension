import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
import jwt
from dotenv import load_dotenv
import structlog
from services.secrets_manager import get_secret_value

load_dotenv()
logger = structlog.get_logger()

SECRET_KEY = get_secret_value("JWT_SECRET", default="", secret_field="JWT_SECRET")
if os.getenv("ENV", "DEV") == "PROD" and not SECRET_KEY:
    raise RuntimeError("JWT_SECRET is required in PROD. Configure AWS Secrets Manager or environment variable.")
if os.getenv("ENV", "DEV") != "PROD" and not SECRET_KEY:
    SECRET_KEY = "dev-only-change-me-very-long-secret-key-32bytes-min"
    logger.info("jwt_secret_fallback_enabled", msg="Using local development JWT fallback key")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
AUTH_DISABLED = os.getenv("AUTH_DISABLED", "true").lower() == "true"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    to_encode["typ"] = "access"
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    to_encode["typ"] = "refresh"
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def _decode_and_validate_token(token: str) -> Dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role not in {"USER", "ADMIN"}:
            raise credentials_exception
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise credentials_exception

def verify_jwt_token(token: str = Depends(oauth2_scheme)):
    if AUTH_DISABLED and not token:
        return {"username": "guest", "role": "ADMIN", "sid": "local"}

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = _decode_and_validate_token(token)
    token_type = payload.get("typ", "access")
    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": payload.get("sub"), "role": payload.get("role"), "sid": payload.get("sid")}

def verify_refresh_token(token: str = Depends(oauth2_scheme)):
    payload = _decode_and_validate_token(token)
    if payload.get("typ") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    sid = payload.get("sid")
    if not sid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": payload.get("sub"), "role": payload.get("role"), "sid": sid}

def verify_token(token: str = Depends(oauth2_scheme)):
    # Backward-compatible alias for existing imports.
    return verify_jwt_token(token)

def require_user(token_data: dict = Depends(verify_jwt_token)):
    if token_data.get("role") not in {"USER", "ADMIN"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User access required."
        )
    return token_data

def require_admin(token_data: dict = Depends(verify_jwt_token)):
    if AUTH_DISABLED:
        return token_data or {"username": "guest", "role": "ADMIN", "sid": "local"}

    if token_data.get("role") != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough privileges. Admin required."
        )
    return token_data
