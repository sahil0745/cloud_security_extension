import os
from dotenv import load_dotenv
load_dotenv()
import time
import uuid
import asyncio
import jwt
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from routes import api, auth_routes
from database.db import engine, Base
from services.logging_config import configure_structlog
import models.models
import structlog
from auth.security import verify_jwt_token
from fastapi import Depends
from sqlalchemy import text
from services.redis_cache import get_redis
from database.db import AsyncSessionLocal
from services.audit_integrity import verify_log_chain
from auth.security import SECRET_KEY, ALGORITHM
from fastapi_limiter import FastAPILimiter
import redis.asyncio as redis

try:
    from prometheus_client import Counter, Histogram
    PROM_METRICS_AVAILABLE = True
except ImportError:
    PROM_METRICS_AVAILABLE = False

# Initialize Structured Logging FIRST
configure_structlog()
logger = structlog.get_logger()

app = FastAPI(
    title="CloudSec Copilot API - Enterprise",
    description="Enterprise-grade Backend for Cloud Security Extension",
    version="2.0.0",
    lifespan=None
)

@asynccontextmanager
async def app_lifespan(application: FastAPI):
    async def _periodic_integrity_check():
        interval = int(os.getenv("LOG_INTEGRITY_VERIFY_INTERVAL_SECONDS", "300"))
        while True:
            try:
                async with AsyncSessionLocal() as db:
                    result = await verify_log_chain(db)
                    if not result.get("valid", False):
                        logger.error("audit_log_chain_tamper_detected", broken_log_id=result.get("broken_log_id"))
            except Exception as exc:
                logger.error("audit_log_periodic_check_failed", error=str(exc))
            await asyncio.sleep(interval)

    logger.info("application_startup", version="2.0.0")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_tables_created")

    # Auto-seed database on first run; preserves existing data on restarts
    from init_db import init_database
    await init_database()

    application.state.rate_limiter_enabled = False
    application.state.rate_limiter_redis = None
    redis_url = os.getenv("RATE_LIMIT_REDIS_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    try:
        redis_client = redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
        await FastAPILimiter.init(redis_client)
        application.state.rate_limiter_enabled = True
        application.state.rate_limiter_redis = redis_client
        logger.info("fastapi_limiter_enabled", redis_url=redis_url)
    except Exception as exc:
        if os.getenv("ENV", "DEV") == "PROD":
            logger.warning("fastapi_limiter_disabled", error=str(exc))
        else:
            logger.info("fastapi_limiter_disabled_dev", error=str(exc))

    verification_task = None
    if os.getenv("ENV", "DEV") == "PROD":
        verification_task = asyncio.create_task(_periodic_integrity_check())
    yield

    if application.state.rate_limiter_redis is not None:
        await application.state.rate_limiter_redis.close()

    if verification_task is not None:
        verification_task.cancel()
        try:
            await verification_task
        except asyncio.CancelledError:
            pass
    logger.info("application_shutdown")

app.router.lifespan_context = app_lifespan

if PROM_METRICS_AVAILABLE:
    REQUEST_COUNTER = Counter("api_requests_total", "Total HTTP requests", ["method", "path", "status"])
    REQUEST_LATENCY = Histogram("api_request_latency_seconds", "HTTP request latency", ["method", "path"])

# ── Security Headers Middleware ──
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if os.getenv("ENV", "DEV") == "PROD":
            forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
            if forwarded_proto != "https":
                https_url = str(request.url).replace("http://", "https://", 1)
                return RedirectResponse(url=https_url, status_code=307)

        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.user = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                request.state.user = {"sub": payload.get("sub"), "role": payload.get("role")}
            except Exception:
                request.state.user = None

        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start

        if PROM_METRICS_AVAILABLE:
            path = request.url.path
            REQUEST_COUNTER.labels(request.method, path, str(response.status_code)).inc()
            REQUEST_LATENCY.labels(request.method, path).observe(elapsed)

        response.headers["X-Request-ID"] = request_id
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

@app.exception_handler(429)
async def rate_limit_handler(request: Request, exc):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."})

allowed_hosts_raw = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in allowed_hosts_raw.split(",") if h.strip()])

# ── CORS ──
cors_origins_raw = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173")
cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── Prometheus Monitoring ──
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
    logger.info("prometheus_metrics_enabled", endpoint="/metrics")
except ImportError:
    logger.warning("prometheus_not_installed", msg="Metrics endpoint disabled")

# ── Routes ──
app.include_router(auth_routes.router, prefix="/api")
app.include_router(api.router, prefix="/api", dependencies=[Depends(verify_jwt_token)])

@app.get("/")
async def root():
    return {"status": "online", "service": "CloudSec Copilot API", "version": "2.0.0"}

@app.get("/health")
async def health_check():
    db_status = "connected"
    redis_status = "connected"

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    try:
        redis_client = await get_redis()
        if redis_client is None:
            redis_status = "unavailable"
        else:
            await redis_client.ping()
    except Exception:
        redis_status = "unavailable"

    overall_status = "healthy" if db_status == "connected" else "degraded"

    return {
        "status": overall_status,
        "database": db_status,
        "redis": redis_status,
        "service": "CloudSec Copilot",
        "version": "2.0.0"
    }
