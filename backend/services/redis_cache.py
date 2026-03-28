"""
Enterprise Redis Cache Service
Handles: risk score caching, OTP storage with TTL, session management.
"""
import os
import json
import time
import structlog
from typing import Any

logger = structlog.get_logger()

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    aioredis = None
    REDIS_AVAILABLE = False

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_redis_pool = None
_redis_retry_after = 0.0
_local_cache: dict[str, tuple[Any, float]] = {}


def _local_set(key: str, value: Any, ttl: int):
    _local_cache[key] = (value, time.time() + max(1, int(ttl)))


def _local_get(key: str):
    item = _local_cache.get(key)
    if not item:
        return None
    value, expires_at = item
    if time.time() > expires_at:
        _local_cache.pop(key, None)
        return None
    return value


def _local_delete(key: str):
    _local_cache.pop(key, None)


def _local_prune(max_items: int = 5000):
    if len(_local_cache) <= max_items:
        return
    now = time.time()
    expired = [k for k, (_, exp) in _local_cache.items() if now > exp]
    for k in expired:
        _local_cache.pop(k, None)
    if len(_local_cache) <= max_items:
        return
    for k in list(_local_cache.keys())[: max(1, len(_local_cache) - max_items)]:
        _local_cache.pop(k, None)

async def get_redis():
    global _redis_pool, _redis_retry_after
    if not REDIS_AVAILABLE:
        logger.warning("redis_not_available", reason="redis.asyncio not installed")
        return None

    now = time.time()
    if _redis_pool is None and now < _redis_retry_after:
        return None

    if _redis_pool is None:
        try:
            _redis_pool = aioredis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=float(os.getenv("REDIS_CONNECT_TIMEOUT", "0.1")),
                socket_timeout=float(os.getenv("REDIS_SOCKET_TIMEOUT", "0.2")),
            )
            await _redis_pool.ping()
            logger.info("redis_connected", url=REDIS_URL)
        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            _redis_pool = None
            _redis_retry_after = now + float(os.getenv("REDIS_RETRY_COOLDOWN_SECONDS", "15"))
    return _redis_pool


class RedisCache:
    @staticmethod
    async def set_risk_score(resource_id: str, score: dict, ttl: int = 300):
        """Cache a risk score for 5 minutes by default."""
        key = f"risk:{resource_id}"
        _local_set(key, score, ttl)
        _local_prune()
        r = await get_redis()
        if r:
            try:
                await r.setex(key, ttl, json.dumps(score))
                logger.info("redis_cache_set", key=key, ttl=ttl)
            except Exception as exc:
                logger.warning("redis_cache_set_failed", key=key, error=str(exc))

    @staticmethod
    async def get_risk_score(resource_id: str):
        """Retrieve cached risk score."""
        key = f"risk:{resource_id}"
        r = await get_redis()
        if r:
            try:
                cached = await r.get(key)
                if cached:
                    logger.info("redis_cache_hit", key=key)
                    return json.loads(cached)
            except Exception as exc:
                logger.warning("redis_cache_get_failed", key=key, error=str(exc))
        return _local_get(key)

    @staticmethod
    async def store_otp(action_id: str, otp: str, ttl: int = 300):
        """Store OTP with 5-minute TTL for approval workflow."""
        key = f"otp:{action_id}"
        _local_set(key, otp, ttl)
        _local_prune()
        r = await get_redis()
        if r:
            try:
                await r.setex(key, ttl, otp)
                logger.info("otp_stored_redis", action_id=action_id, ttl=ttl)
            except Exception as exc:
                logger.warning("otp_store_redis_failed", action_id=action_id, error=str(exc))

    @staticmethod
    async def verify_otp(action_id: str, otp: str) -> bool:
        """Verify OTP from Redis."""
        key = f"otp:{action_id}"
        r = await get_redis()
        if r:
            try:
                stored = await r.get(key)
                if stored and stored == otp:
                    await r.delete(key)
                    _local_delete(key)
                    return True
            except Exception as exc:
                logger.warning("otp_verify_redis_failed", action_id=action_id, error=str(exc))
        local_stored = _local_get(key)
        if local_stored and local_stored == otp:
            _local_delete(key)
            return True
        return False

    @staticmethod
    async def cache_session(session_id: str, user_data: dict, ttl: int = 3600):
        """Cache user session for 1 hour."""
        key = f"session:{session_id}"
        _local_set(key, user_data, ttl)
        _local_prune()
        r = await get_redis()
        if r:
            try:
                await r.setex(key, ttl, json.dumps(user_data))
            except Exception as exc:
                logger.warning("session_cache_set_failed", sid=session_id, error=str(exc))

    @staticmethod
    async def get_session(session_id: str):
        """Retrieve cached session."""
        key = f"session:{session_id}"
        r = await get_redis()
        if r:
            try:
                cached = await r.get(key)
                if cached:
                    return json.loads(cached)
            except Exception as exc:
                logger.warning("session_cache_get_failed", sid=session_id, error=str(exc))
        return _local_get(key)


redis_cache = RedisCache()
