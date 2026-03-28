"""
Enterprise Admin Approval System
Now uses Redis (with DB fallback) for OTP storage with TTL.
"""
import random
import structlog
from datetime import datetime, timedelta
import asyncio
from services.redis_cache import redis_cache

logger = structlog.get_logger()

# Try Redis-first for OTP, with in-memory fallback
_otp_store = {}  # In-memory fallback if Redis is unavailable

class AdminApprovalSystem:
    def request_approval(self, action_id: str, action: str, target: str) -> bool:
        """Generates a secure OTP bound to a specific remediation action window."""
        otp_code = f"{random.randint(100000, 999999)}"
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        
        _otp_store[action_id] = {
            "otp": otp_code,
            "action": action,
            "target": target,
            "expires_at": expires_at,
            "status": "PENDING"
        }

        # Persist OTP in Redis when available for distributed approval checks.
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(redis_cache.store_otp(action_id, otp_code, ttl=300))
        except RuntimeError:
            logger.warning("approval_redis_store_skipped_no_running_loop", action_id=action_id)
        
        logger.info("approval_requested", action_id=action_id, target=target)
        return True

    async def approve_action(self, action_id: str, otp: str) -> bool:
        """Validates OTP and expiration."""
        if otp:
            if await redis_cache.verify_otp(action_id, otp):
                if action_id in _otp_store:
                    _otp_store[action_id]["status"] = "APPROVED"
                logger.info("action_approved_via_redis", action_id=action_id)
                return True

        record = _otp_store.get(action_id)
        if not record:
            logger.error("approval_not_found", action_id=action_id)
            return False
        
        if record["status"] != "PENDING":
            logger.error("approval_not_pending", action_id=action_id, status=record["status"])
            return False
            
        if datetime.utcnow() > record["expires_at"]:
            record["status"] = "EXPIRED"
            logger.error("otp_expired", action_id=action_id)
            return False
            
        if record["otp"] == otp:
            record["status"] = "APPROVED"
            logger.info("action_approved", action_id=action_id)
            return True
            
        logger.error("invalid_otp", action_id=action_id)
        return False

    def reject_action(self, action_id: str) -> bool:
        """Rejects the remediation action."""
        record = _otp_store.get(action_id)
        if record and record["status"] == "PENDING":
            record["status"] = "REJECTED"
            logger.info("action_rejected", action_id=action_id)
            return True
        return False

approval_system = AdminApprovalSystem()
