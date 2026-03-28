import time
import jwt
from fastapi import Request, Response
from fastapi_limiter.depends import RateLimiter
from auth.security import SECRET_KEY, ALGORITHM

_local_windows = {}


async def user_identifier(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if isinstance(user, dict):
        subject = user.get("sub") or user.get("username")
        if subject:
            return f"user:{subject}"

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            subject = payload.get("sub")
            if subject:
                return f"user:{subject}"
        except Exception:
            pass

    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return f"ip:{ip}"


def create_rate_limiter(times: int, seconds: int, scope: str):
    async def dependency(request: Request, response: Response):
        if not getattr(request.app.state, "rate_limiter_enabled", False):
            identity = await user_identifier(request)
            window = int(time.time() // seconds)
            key = f"{scope}:{identity}:{seconds}:{window}"
            current = _local_windows.get(key, 0) + 1
            _local_windows[key] = current
            if current > times:
                from fastapi import HTTPException
                raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")
            return
        limiter = RateLimiter(times=times, seconds=seconds, identifier=user_identifier)
        await limiter(request, response)

    return dependency
