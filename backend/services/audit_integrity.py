import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models.models import Logs


def _hash_log(previous_hash: str, event_type: str, description: str, resource_id: str, user_id: int, timestamp_iso: str) -> str:
    payload = {
        "previous_hash": previous_hash,
        "event_type": event_type or "",
        "description": description or "",
        "resource_id": resource_id or "",
        "user_id": user_id,
        "timestamp": timestamp_iso,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def append_tamper_proof_log(
    db: AsyncSession,
    event_type: str,
    description: str,
    resource_id: str = None,
    user_id: int = None,
):
    latest = await db.execute(select(Logs).order_by(Logs.id.desc()).limit(1))
    prev = latest.scalars().first()
    previous_hash = prev.log_hash if prev and prev.log_hash else "GENESIS"

    ts = datetime.now(timezone.utc)
    ts_iso = ts.isoformat()
    current_hash = _hash_log(previous_hash, event_type, description, resource_id, user_id, ts_iso)

    log = Logs(
        event_type=event_type,
        description=description,
        resource_id=resource_id,
        user_id=user_id,
        timestamp=ts,
        previous_hash=previous_hash,
        log_hash=current_hash,
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)
    return log


async def verify_log_chain(db: AsyncSession):
    result = await db.execute(select(Logs).order_by(Logs.id.asc()))
    logs = list(result.scalars().all())
    if not logs:
        return {"valid": True, "broken_log_id": None, "checked": 0}

    # Legacy records may exist from before hash-chaining rollout.
    hashed_logs = [l for l in logs if l.log_hash and l.previous_hash]
    if not hashed_logs:
        return {"valid": True, "broken_log_id": None, "checked": 0}

    expected_previous = "GENESIS"
    for log in hashed_logs:
        ts = log.timestamp
        if ts is None:
            return {"valid": False, "broken_log_id": log.id, "checked": len(hashed_logs)}

        timestamp_iso = ts.isoformat()
        expected_hash = _hash_log(
            expected_previous,
            log.event_type,
            log.description,
            log.resource_id,
            log.user_id,
            timestamp_iso,
        )
        if log.previous_hash != expected_previous or log.log_hash != expected_hash:
            return {"valid": False, "broken_log_id": log.id, "checked": len(hashed_logs)}

        expected_previous = log.log_hash

    return {"valid": True, "broken_log_id": None, "checked": len(hashed_logs)}
