import os
import sys
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import pytest

ROOT_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
TEST_DB_FILE = os.path.join(BACKEND_DIR, "test_production_readiness.db")

if os.path.exists(TEST_DB_FILE):
    os.remove(TEST_DB_FILE)

# Force test-safe environment before importing backend modules.
os.environ["ENV"] = "DEV"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_production_readiness.db"
os.environ["ADMIN_BOOTSTRAP_TOKEN"] = "test-bootstrap-token"
os.environ["AES_ENCRYPTION_KEY"] = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

sys.path.insert(0, BACKEND_DIR)
os.chdir(BACKEND_DIR)

from fastapi.testclient import TestClient
from main import app
from services.encryption import DBEncryption
from services.redis_cache import redis_cache
from auth.security import create_access_token, create_refresh_token
from database.db import AsyncSessionLocal, engine
from models.models import User, AuditLog, ConfigHistory, RiskHistory
from sqlalchemy import select, text
from services import cloud_service as cloud_service_module
from services.remediation import actions as remediation_actions_module
from services.rules_engine.evaluator import RuleEvaluator
from services.rules_engine.severity import calculate_risk_score
from ml_engine import engine as ml_runtime_engine


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _auth_header(token: str):
    return {"Authorization": f"Bearer {token}"}


async def _ensure_user(username: str, role: str):
    async with AsyncSessionLocal() as session:
        found = await session.execute(select(User).filter(User.username == username))
        if found.scalars().first() is None:
            session.add(User(username=username, hashed_password="test_hash", role=role))
            await session.commit()


async def _seed_audit_logs(username: str, count: int = 12):
    async with AsyncSessionLocal() as session:
        user_result = await session.execute(select(User).filter(User.username == username))
        user = user_result.scalars().first()
        if user is None:
            user = User(username=username, hashed_password="seed_hash", role="ADMIN")
            session.add(user)
            await session.commit()
            await session.refresh(user)

        for i in range(count):
            session.add(AuditLog(user_id=user.id, action=f"iam_policy_change_{i}", resource="s3://critical-bucket", status="denied"))
        await session.commit()


async def _seed_config_history_rows(platforms: list[str]):
    async with AsyncSessionLocal() as session:
        for platform in platforms:
            session.add(
                ConfigHistory(
                    baseline_id=None,
                    platform=platform,
                    configuration={"seed": True, "platform": platform},
                    drift_detected={},
                )
            )
        await session.commit()


async def _seed_risk_history_rows(scores: list[int]):
    async with AsyncSessionLocal() as session:
        base_ts = datetime(2099, 1, 1, 1, 7, tzinfo=timezone.utc)
        for idx, score in enumerate(scores):
            session.add(
                RiskHistory(
                    score=int(score),
                    vulnerabilities_count=max(0, int(score) // 10),
                    timestamp=base_ts + timedelta(hours=idx * 2),
                )
            )
        await session.commit()


async def _seed_audit_actions_for_user(username: str, actions: list[str]):
    async with AsyncSessionLocal() as session:
        user_result = await session.execute(select(User).filter(User.username == username))
        user = user_result.scalars().first()
        if user is None:
            user = User(username=username, hashed_password="seed_hash", role="ADMIN")
            session.add(user)
            await session.commit()
            await session.refresh(user)

        for action in actions:
            session.add(AuditLog(user_id=user.id, action=action, resource="audit://vector", status="denied"))
        await session.commit()


def _create_token_with_user(role: str):
    username = f"{role.lower()}_{uuid.uuid4().hex[:10]}"
    asyncio.run(_ensure_user(username, role))
    return create_access_token({"sub": username, "role": role})


def test_all_api_endpoints_require_jwt(client):
    response = client.get("/api/alerts")
    assert response.status_code == 401


def test_remediation_admin_only(client):
    user_token = _create_token_with_user("USER")
    response = client.post(
        "/api/remediate",
        headers={
            **_auth_header(user_token),
            "X-Remediation-Confirm": "CONFIRM_REMEDIATE",
        },
        json={
            "risk_data": {
                "risk_level": "MEDIUM",
                "resource_id": "sg-test",
                "explanation": "open port",
            },
            "confirmation_flag": True,
            "confirmation_phrase": "I_UNDERSTAND_THE_IMPACT",
        },
    )
    assert response.status_code == 403


def test_remediation_double_validation_required(client):
    admin_token = _create_token_with_user("ADMIN")

    response = client.post(
        "/api/remediate",
        headers=_auth_header(admin_token),
        json={
            "risk_data": {
                "risk_level": "MEDIUM",
                "resource_id": "sg-test",
                "explanation": "open port",
            },
            "confirmation_flag": False,
            "confirmation_phrase": "INVALID_CONFIRMATION",
        },
    )
    assert response.status_code == 400


def test_remediation_admin_with_double_validation_succeeds(client):
    admin_token = _create_token_with_user("ADMIN")

    response = client.post(
        "/api/remediate",
        headers={
            **_auth_header(admin_token),
            "X-Remediation-Confirm": "CONFIRM_REMEDIATE",
        },
        json={
            "risk_data": {
                "risk_level": "MEDIUM",
                "resource_id": "sg-test",
                "explanation": "open port",
            },
            "confirmation_flag": True,
            "confirmation_phrase": "I_UNDERSTAND_THE_IMPACT",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_remediation_success_returns_task_id(monkeypatch, client):
    class _FakeTask:
        id = "task-remediate-123"

    class _FakeQueue:
        @staticmethod
        def delay(*_args, **_kwargs):
            return _FakeTask()

    async def _noop_tamper(*_args, **_kwargs):
        return None

    monkeypatch.setattr("routes.api.run_remediation_task", _FakeQueue)
    monkeypatch.setattr("routes.api.append_tamper_proof_log", _noop_tamper)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/remediate",
        headers={
            **_auth_header(admin_token),
            "X-Remediation-Confirm": "CONFIRM_REMEDIATE",
        },
        json={
            "risk_data": {
                "risk_level": "HIGH",
                "resource_id": "sg-test-1",
                "explanation": "open ingress",
            },
            "confirmation_flag": True,
            "confirmation_phrase": "I_UNDERSTAND_THE_IMPACT",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["task_id"] == "task-remediate-123"


def test_remediation_queue_failure_returns_500(monkeypatch, client):
    class _BrokenQueue:
        @staticmethod
        def delay(*_args, **_kwargs):
            raise RuntimeError("queue unavailable")

    monkeypatch.setattr("routes.api.run_remediation_task", _BrokenQueue)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/remediate",
        headers={
            **_auth_header(admin_token),
            "X-Remediation-Confirm": "CONFIRM_REMEDIATE",
        },
        json={
            "risk_data": {
                "risk_level": "HIGH",
                "resource_id": "sg-test-2",
                "explanation": "open ingress",
            },
            "confirmation_flag": True,
            "confirmation_phrase": "I_UNDERSTAND_THE_IMPACT",
        },
    )
    assert response.status_code == 500


def test_database_encryption_and_rotation_round_trip():
    payload = {"secret": "value", "nested": {"x": 1}}
    encrypted = DBEncryption.encrypt_json(payload)
    assert encrypted and isinstance(encrypted, str)

    decrypted = DBEncryption.decrypt_json(encrypted)
    assert decrypted == payload

    rotated = DBEncryption.rotate_payload(encrypted)
    assert DBEncryption.decrypt_json(rotated) == payload


def test_config_history_configuration_encrypted_at_rest(client):
    sentinel = f"plain-secret-{uuid.uuid4().hex[:8]}"

    async def _write_and_read_raw():
        async with AsyncSessionLocal() as session:
            row = ConfigHistory(
                baseline_id=None,
                platform="aws",
                configuration={"secret": sentinel, "flag": True},
                drift_detected={"changed": ["x"]},
            )
            session.add(row)
            await session.commit()

        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT configuration FROM config_history ORDER BY id DESC LIMIT 1")
            )
            return result.scalar()

    raw_value = asyncio.run(_write_and_read_raw())
    assert isinstance(raw_value, str)
    assert sentinel not in raw_value
    assert raw_value.startswith("k0:")


def test_redis_cache_round_trip(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.store = {}

        async def setex(self, key, ttl, value):
            self.store[key] = value

        async def get(self, key):
            return self.store.get(key)

        async def delete(self, key):
            self.store.pop(key, None)

    fake = FakeRedis()

    async def _fake_get_redis():
        return fake

    monkeypatch.setattr("services.redis_cache.get_redis", _fake_get_redis)

    asyncio.run(redis_cache.set_risk_score("resource-1", {"risk_score": 77}))
    cached = asyncio.run(redis_cache.get_risk_score("resource-1"))
    assert cached["risk_score"] == 77


def test_evaluate_risk_returns_completed_with_action_and_score(monkeypatch, client):
    async def _no_cache(_resource_id):
        return None

    async def _cache_set(*_args, **_kwargs):
        return None

    monkeypatch.setattr("routes.api.redis_cache.get_risk_score", _no_cache)
    monkeypatch.setattr("routes.api.redis_cache.set_risk_score", _cache_set)

    admin_token = _create_token_with_user("ADMIN")

    response = client.post(
        "/api/evaluate-risk",
        headers=_auth_header(admin_token),
        json={
            "violations": [{"severity": "HIGH"}, {"severity": "MEDIUM"}],
            "ml_prediction": {"risk_score": 74, "confidence": 0.93},
            "behavior_analysis": {"score": 66},
            "asset_context": {
                "resource_id": f"risk-{uuid.uuid4().hex[:8]}",
                "criticality_score": "critical",
                "repeats_in_24h": 5,
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    risk_data = payload["risk_data"]
    assert isinstance(risk_data.get("risk_score"), int)
    assert risk_data.get("risk_level") in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert risk_data.get("action") in ("ALLOW", "LOG_ONLY", "WARNING", "ADMIN_APPROVAL", "AUTO_REMEDIATION")
    assert risk_data.get("recommended_action")


def test_evaluate_risk_returns_cached_when_entry_exists(monkeypatch, client):
    cached_payload = {
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "action": "AUTO_REMEDIATION",
        "confidence": 0.91,
        "explanation": "cached",
        "recommended_action": "Immediate alert",
    }

    async def _get_cached(_resource_id):
        return cached_payload

    monkeypatch.setattr("routes.api.redis_cache.get_risk_score", _get_cached)

    admin_token = _create_token_with_user("ADMIN")

    response = client.post(
        "/api/evaluate-risk",
        headers=_auth_header(admin_token),
        json={
            "violations": [],
            "ml_prediction": {},
            "behavior_analysis": {},
            "asset_context": {"resource_id": "risk-cached"},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "cached"
    assert payload["risk_data"]["risk_score"] == 88
    assert payload["risk_data"]["action"] == "AUTO_REMEDIATION"


def test_ml_prediction_runs_async_endpoint(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/ml-predict",
        headers=_auth_header(admin_token),
        json={"public_access": "true", "permission_level": 9},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "queued"


def test_ml_prediction_falls_back_to_local_inference_on_queue_failure(monkeypatch, client):
    class _BrokenQueue:
        @staticmethod
        def delay(*_args, **_kwargs):
            raise RuntimeError("broker unavailable")

    def _fake_predict(_features):
        return {
            "prediction": "RISK",
            "confidence": 0.82,
            "anomaly_score": 0.6,
            "risk_score": 62,
            "insights": {},
        }

    monkeypatch.setattr("routes.api.run_ml_inference_task", _BrokenQueue)
    monkeypatch.setattr("routes.api.ml_engine.predict", _fake_predict)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/ml-predict",
        headers=_auth_header(admin_token),
        json={"public_access": "true", "permission_level": 9},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed-local"
    assert payload["result"]["prediction"] == "RISK"


def test_health_endpoint_reports_core_dependencies(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "database" in body
    assert "redis" in body


def test_security_headers_are_present(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in (response.headers.get("Content-Security-Policy") or "")
    assert response.headers.get("Permissions-Policy")


def test_admin_can_search_audit_logs(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get(
        "/api/logs/search",
        headers=_auth_header(admin_token),
        params={"limit": 10, "offset": 0},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert "records" in payload


def test_cloud_fetch_config_aws_returns_data(monkeypatch):
    class FakeS3Client:
        def list_buckets(self):
            return {"Buckets": [{"Name": "b1"}]}

        def get_public_access_block(self, Bucket):
            return {"PublicAccessBlockConfiguration": {"BlockPublicPolicy": True}}

        def get_bucket_policy(self, Bucket):
            return {"Policy": "{}"}

    class FakeIAMPaginator:
        def paginate(self):
            return [{"Roles": [{"RoleName": "role1", "Arn": "arn:aws:iam::1:role/role1"}]}]

    class FakeIAMClient:
        def get_paginator(self, _):
            return FakeIAMPaginator()

    class FakeEC2Paginator:
        def __init__(self, pages):
            self.pages = pages

        def paginate(self):
            return self.pages

    class FakeEC2Client:
        def get_paginator(self, name):
            if name == "describe_security_groups":
                return FakeEC2Paginator([{"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "default", "IpPermissions": []}]}])
            return FakeEC2Paginator([{"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}}]}]}])

    class FakeBoto3:
        @staticmethod
        def client(name):
            if name == "s3":
                return FakeS3Client()
            if name == "iam":
                return FakeIAMClient()
            if name == "ec2":
                return FakeEC2Client()
            raise ValueError(name)

    monkeypatch.setattr(cloud_service_module, "boto3", FakeBoto3)
    result = cloud_service_module.CloudService.fetch_aws_config()
    assert "s3_buckets" in result
    assert "iam_roles" in result
    assert "security_groups" in result
    assert "ec2_instances" in result


def test_remediation_cloud_action_executes(monkeypatch):
    calls = {"revoked": False}

    class FakeEC2Client:
        def revoke_security_group_ingress(self, **kwargs):
            calls["revoked"] = True

    class FakeBoto3:
        @staticmethod
        def client(name):
            if name == "ec2":
                return FakeEC2Client()
            raise ValueError(name)

    monkeypatch.setattr(remediation_actions_module, "boto3", FakeBoto3)
    ok = remediation_actions_module.CloudActions.close_open_ports("sg-123")
    assert ok is True
    assert calls["revoked"] is True


def test_ml_retraining_endpoint_possible(client):
    admin_token = _create_token_with_user("ADMIN")
    payload = create_access_token({"sub": "ml_admin", "role": "ADMIN"})
    assert payload

    asyncio.run(_seed_audit_logs("ml_admin", 12))

    response = client.post(
        "/api/ml/retrain",
        headers=_auth_header(create_access_token({"sub": "ml_admin", "role": "ADMIN"})),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_rate_limiting_triggers_429_for_strict_endpoint(client):
    admin_token = _create_token_with_user("ADMIN")
    first = client.post(
        "/api/approve-action/action-1",
        headers=_auth_header(admin_token),
        params={"otp": "111111"},
    )
    second = client.post(
        "/api/approve-action/action-1",
        headers=_auth_header(admin_token),
        params={"otp": "111111"},
    )
    assert first.status_code in (200, 404, 429)
    assert second.status_code in (200, 404, 429)
    assert first.status_code == 429 or second.status_code == 429


def test_verify_logs_integrity_endpoint(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/verify-logs-integrity", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in ("valid", "tampered")
    assert "checked" in payload


def test_task_status_endpoint_for_ml_task(client):
    admin_token = _create_token_with_user("ADMIN")
    queued = client.post(
        "/api/ml-predict",
        headers=_auth_header(admin_token),
        json={"public_access": "true", "permission_level": 9},
    )
    if queued.status_code == 429:
        return

    task_id = queued.json().get("task_id")
    assert task_id
    status_resp = client.get(f"/api/task-status/{task_id}", headers=_auth_header(admin_token))
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] in ("pending", "running", "completed", "failed")


def test_refresh_endpoint_rotates_tokens_for_active_session(client):
    username = f"refresh_user_{uuid.uuid4().hex[:8]}"
    sid = str(uuid.uuid4())
    asyncio.run(_ensure_user(username, "ADMIN"))
    asyncio.run(redis_cache.cache_session(sid, {"username": username, "role": "ADMIN"}, ttl=3600))

    refresh_token = create_refresh_token({"sub": username, "role": "ADMIN", "sid": sid})

    refresh_response = client.post(
        "/api/auth/refresh",
        headers=_auth_header(refresh_token),
    )
    assert refresh_response.status_code == 200
    refresh_payload = refresh_response.json()
    assert refresh_payload["token_type"] == "bearer"
    assert refresh_payload["access_token"]
    assert refresh_payload["refresh_token"]


def test_refresh_endpoint_rejects_access_tokens(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.post("/api/auth/refresh", headers=_auth_header(admin_token))
    assert response.status_code == 401


def test_user_cannot_export_reports(client):
    user_token = _create_token_with_user("USER")
    response = client.get("/api/export", headers=_auth_header(user_token), params={"format": "csv"})
    assert response.status_code == 403


def test_webhook_health_requires_admin(client):
    user_token = _create_token_with_user("USER")
    denied = client.get("/api/webhook-health", headers=_auth_header(user_token))
    assert denied.status_code == 403

    admin_token = _create_token_with_user("ADMIN")
    allowed = client.get("/api/webhook-health", headers=_auth_header(admin_token))
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload.get("status") == "success"
    assert isinstance(payload.get("channels"), dict)


def test_admin_generate_report_with_filters_and_compliance(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get(
        "/api/generate-report",
        headers=_auth_header(admin_token),
        params={
            "severity": "HIGH",
            "compliance_mode": "true",
            "compliance_standard": "SOC2",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert "overview" in payload
    assert "vulnerabilities" in payload
    assert "risk_analysis" in payload
    assert "user_behavior" in payload
    assert "remediation_actions" in payload
    assert "timeline" in payload
    assert payload.get("metadata", {}).get("compliance", {}).get("standard") == "SOC2"


def test_admin_export_csv_and_pdf_reports(client):
    admin_token = _create_token_with_user("ADMIN")

    csv_response = client.get("/api/export-csv", headers=_auth_header(admin_token))
    assert csv_response.status_code == 200
    assert "text/csv" in (csv_response.headers.get("content-type") or "")
    assert "Category,ID,Item" in csv_response.text

    pdf_response = client.get("/api/export-pdf", headers=_auth_header(admin_token))
    assert pdf_response.status_code == 200
    assert "application/pdf" in (pdf_response.headers.get("content-type") or "")
    assert pdf_response.content.startswith(b"%PDF")


def test_admin_export_csv_via_signed_url(client):
    admin_token = _create_token_with_user("ADMIN")
    signed_response = client.get(
        "/api/export",
        headers=_auth_header(admin_token),
        params={"format": "csv", "use_signed_url": "true"},
    )
    assert signed_response.status_code == 200
    payload = signed_response.json()
    assert payload.get("status") == "signed"
    assert payload.get("artifact_id")
    assert payload.get("download_url")

    download_path = payload["download_url"]
    download_response = client.get(download_path, headers=_auth_header(admin_token))
    assert download_response.status_code == 200
    assert "text/csv" in (download_response.headers.get("content-type") or "")
    assert "Category,ID,Item" in download_response.text


def test_signed_report_artifact_denies_different_user(client):
    owner_token = _create_token_with_user("ADMIN")
    other_token = _create_token_with_user("ADMIN")

    signed_response = client.get(
        "/api/export",
        headers=_auth_header(owner_token),
        params={"format": "csv", "use_signed_url": "true"},
    )
    assert signed_response.status_code == 200
    payload = signed_response.json()
    assert payload.get("download_url")

    forbidden_download = client.get(payload["download_url"], headers=_auth_header(other_token))
    assert forbidden_download.status_code == 403
    assert "Artifact access denied" in forbidden_download.text


def test_user_cannot_request_global_scope_reports(client):
    user_token = _create_token_with_user("USER")
    response = client.get(
        "/api/generate-report",
        headers=_auth_header(user_token),
        params={"scope": "global"},
    )
    assert response.status_code == 403
    assert "Global report scope requires admin role" in response.text


def test_reports_ui_has_preview_modal_controls():
    reports_path = os.path.join(ROOT_DIR, "src", "components", "Reports.tsx")
    with open(reports_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "Report Preview" in content
    assert "Confirm & Download" in content
    assert "Global Scope" in content


def test_report_schedule_create_and_list(client):
    admin_token = _create_token_with_user("ADMIN")
    create = client.post(
        "/api/report-schedules",
        headers=_auth_header(admin_token),
        json={
            "frequency": "daily",
            "report_format": "pdf",
            "severity": "HIGH",
            "compliance_mode": True,
            "compliance_standard": "ISO",
        },
    )
    assert create.status_code == 200
    payload = create.json()
    assert payload.get("status") == "scheduled"
    assert payload.get("schedule", {}).get("frequency") == "daily"

    listed = client.get("/api/report-schedules", headers=_auth_header(admin_token))
    assert listed.status_code == 200
    assert isinstance(listed.json().get("schedules"), list)


def test_report_email_endpoint_uses_generator(monkeypatch, client):
    async def _fake_send(*_args, **_kwargs):
        return {"sent": True, "recipient": "admin@example.com", "format": "pdf"}

    monkeypatch.setattr("routes.api.report_generator.send_report_email_async", _fake_send)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/report-email",
        headers=_auth_header(admin_token),
        json={
            "recipient_email": "admin@example.com",
            "report_format": "pdf",
            "compliance_mode": True,
            "compliance_standard": "SOC2",
        },
    )
    assert response.status_code == 200
    assert response.json().get("sent") is True


def test_evaluate_risk_concurrent_requests_are_stable(client):
    admin_token = _create_token_with_user("ADMIN")
    headers = {**_auth_header(admin_token), "Content-Type": "application/json"}

    def _call(idx: int):
        payload = {
            "violations": [{"severity": "HIGH"}],
            "ml_prediction": {"risk_score": 66, "confidence": 0.91},
            "behavior_analysis": {"score": 52},
            "asset_context": {
                "resource_id": f"concurrent-risk-{idx}-{uuid.uuid4().hex[:6]}",
                "criticality_score": 42,
                "repeats_in_24h": 0,
            },
        }
        resp = client.post("/api/evaluate-risk", headers=headers, json=payload)
        body = resp.json()
        return resp.status_code, body.get("status"), bool(body.get("risk_data"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(16)))

    assert all(code in {200, 429} for code, _status, _has_data in results)
    ok_results = [(status, has_data) for code, status, has_data in results if code == 200]
    assert len(ok_results) >= 1
    assert all(status in {"completed", "cached"} for status, _has_data in ok_results)
    assert all(has_data is True for _status, has_data in ok_results)


def test_trigger_critical_alert_report_endpoint_uses_generator(monkeypatch, client):
    async def _fake_trigger(*_args, **_kwargs):
        return {
            "triggered": True,
            "event_type": "privilege_escalation",
            "severity": "CRITICAL",
            "report_summary": {"total_vulns": 1, "risk_score": 88},
            "email": None,
        }

    monkeypatch.setattr("routes.api.report_generator.trigger_alert_report_async", _fake_trigger)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/report-alert/critical",
        headers=_auth_header(admin_token),
        params={"event_type": "privilege_escalation"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "success"
    assert payload.get("triggered") is True
    assert payload.get("event_type") == "privilege_escalation"


def test_user_cannot_schedule_global_report(client):
    user_token = _create_token_with_user("USER")
    response = client.post(
        "/api/report-schedules",
        headers=_auth_header(user_token),
        json={
            "frequency": "daily",
            "report_format": "pdf",
            "scope": "global",
        },
    )
    assert response.status_code == 403
    assert "Global report scope requires admin role" in response.text


def test_reports_ui_has_download_buttons():
    reports_path = os.path.join(ROOT_DIR, "src", "components", "Reports.tsx")
    with open(reports_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "Download CSV" in content
    assert "Download PDF" in content


def test_attack_path_simulation_endpoint_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/attack-path", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in ("simulated", "clear")
    assert "summary" in payload
    assert "nodes" in payload and isinstance(payload["nodes"], list)
    assert "edges" in payload and isinstance(payload["edges"], list)
    assert "recommendations" in payload and isinstance(payload["recommendations"], list)


def test_attack_path_simulation_active_branch(monkeypatch, client):
    async def _fake_get_alerts(_db):
        return [
            {
                "id": 1,
                "resource": "s3://prod-public",
                "type": "Public bucket exposure",
                "severity": "HIGH",
                "riskScore": 86,
                "status": "Open",
                "timestamp": "",
            },
            {
                "id": 2,
                "resource": "iam-admin-role",
                "type": "IAM privilege escalation path",
                "severity": "CRITICAL",
                "riskScore": 94,
                "status": "Open",
                "timestamp": "",
            },
        ]

    monkeypatch.setattr("routes.api.get_alerts", _fake_get_alerts)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/attack-path", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "simulated"
    assert payload["summary"]["activePaths"] >= 2
    assert payload["summary"]["totalNodes"] >= 4
    assert payload["summary"]["totalEdges"] >= 4
    assert len(payload["recommendations"]) >= 1


def test_behavior_anomalies_endpoint_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/behavior", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert "score" in payload
    assert payload["status"] in ("Normal", "Suspicious", "Critical")
    assert "insights" in payload and isinstance(payload["insights"], list)
    assert "timeline" in payload and isinstance(payload["timeline"], list)
    assert "risk_evolution" in payload and isinstance(payload["risk_evolution"], list)
    assert "heatmap" in payload and isinstance(payload["heatmap"], dict)
    assert "anomalies" in payload and isinstance(payload["anomalies"], list)


def test_behavior_anomalies_active_branch(client):
    admin_username = f"behavior_admin_{uuid.uuid4().hex[:8]}"
    asyncio.run(_ensure_user(admin_username, "ADMIN"))
    asyncio.run(_seed_audit_logs(admin_username, 8))

    admin_token = create_access_token({"sub": admin_username, "role": "ADMIN"})
    response = client.get("/api/dashboard/behavior", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert payload["score"] > 0
    assert payload["status"] in ("Suspicious", "Critical")
    assert len(payload["anomalies"]) >= 1
    assert any(int(a.get("score", 0)) >= 68 for a in payload["anomalies"])


def test_log_user_activity_tolerates_tamper_log_failures(monkeypatch, client):
    async def _fail_append(*_args, **_kwargs):
        raise RuntimeError("simulated tamper log storage failure")

    monkeypatch.setattr("routes.api.append_tamper_proof_log", _fail_append)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/log-user-activity",
        headers=_auth_header(admin_token),
        json={
            "action": "policy_delete_attempt",
            "resource": "iam-admin-role",
            "status": "denied",
        },
    )
    assert response.status_code == 200
    assert response.json().get("status") == "success"


def test_alerts_endpoint_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/alerts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    if payload:
        first = payload[0]
        assert "id" in first
        assert "resource" in first
        assert "type" in first
        assert "severity" in first
        assert "riskScore" in first
        assert "status" in first
        assert "timestamp" in first


def test_dashboard_vulnerabilities_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/vulnerabilities", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    if payload:
        first = payload[0]
        assert isinstance(first.get("id"), str)
        assert first["id"].startswith("VULN-")
        assert "title" in first
        assert "resource" in first
        assert "severity" in first
        assert "status" in first


def test_dashboard_vulnerabilities_active_branch(monkeypatch, client):
    async def _fake_get_alerts(_db):
        return [
            {
                "id": 1,
                "resource": "s3://prod-public",
                "type": "Public bucket exposure",
                "severity": "HIGH",
                "riskScore": 86,
                "status": "Open",
                "timestamp": "",
            },
            {
                "id": 2,
                "resource": "iam-admin-role",
                "type": "IAM privilege escalation path",
                "severity": "CRITICAL",
                "riskScore": 94,
                "status": "Pending Approval",
                "timestamp": "",
            },
        ]

    monkeypatch.setattr("routes.api.get_alerts", _fake_get_alerts)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/vulnerabilities", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 2
    assert payload[0]["id"] == "VULN-001"
    assert payload[0]["severity"] == "HIGH"
    assert payload[1]["id"] == "VULN-002"
    assert payload[1]["severity"] == "CRITICAL"
    assert payload[1]["status"] == "Pending Approval"


def test_dashboard_charts_heatmap_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert "riskTrend" in payload and isinstance(payload["riskTrend"], list)
    assert "attackVectors" in payload and isinstance(payload["attackVectors"], list)
    assert "severityDistribution" in payload and isinstance(payload["severityDistribution"], list)
    assert "heatmap" in payload and isinstance(payload["heatmap"], list)


def test_dashboard_charts_heatmap_populated_branch(monkeypatch, client):
    async def _fake_latest_violations_and_score(_db):
        return ([], 0)

    monkeypatch.setattr("routes.api._latest_violations_and_score", _fake_latest_violations_and_score)

    prefix = f"heatmap-{uuid.uuid4().hex[:8]}"
    asyncio.run(
        _seed_config_history_rows(
            [
                f"{prefix}-aws",
                f"{prefix}-aws",
                f"{prefix}-azure",
            ]
        )
    )

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()

    by_region = {row.get("region"): row for row in payload.get("heatmap", [])}
    assert f"{prefix}-aws" in by_region
    assert f"{prefix}-azure" in by_region
    assert by_region[f"{prefix}-aws"]["db"] >= 6
    assert by_region[f"{prefix}-aws"]["storage"] >= 4
    assert by_region[f"{prefix}-aws"]["network"] >= 4
    assert by_region[f"{prefix}-aws"]["iam"] >= 4
    assert by_region[f"{prefix}-azure"]["db"] >= 3


def test_dashboard_charts_severity_distribution_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    dist = payload.get("severityDistribution", [])
    assert isinstance(dist, list)
    assert len(dist) == 4
    names = [row.get("name") for row in dist]
    assert names == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_dashboard_charts_severity_distribution_active_branch(monkeypatch, client):
    async def _fake_latest_violations_and_score(_db):
        return (
            [
                {"severity": "LOW"},
                {"severity": "MEDIUM"},
                {"severity": "HIGH"},
                {"severity": "CRITICAL"},
                {"severity": "SEVERE"},
                {"severity": None},
            ],
            71,
        )

    monkeypatch.setattr("routes.api._latest_violations_and_score", _fake_latest_violations_and_score)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()

    by_name = {row.get("name"): int(row.get("value", 0)) for row in payload.get("severityDistribution", [])}
    assert by_name["LOW"] == 3
    assert by_name["MEDIUM"] == 1
    assert by_name["HIGH"] == 1
    assert by_name["CRITICAL"] == 1


def test_dashboard_charts_risk_trend_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    trend = payload.get("riskTrend", [])
    assert isinstance(trend, list)
    for point in trend:
        assert "time" in point
        assert "risk" in point
        assert isinstance(point["risk"], int)


def test_dashboard_charts_risk_trend_populated_branch(client):
    asyncio.run(_seed_risk_history_rows([17, 39, 64]))

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    trend = payload.get("riskTrend", [])
    assert len(trend) >= 3

    by_time = {point.get("time"): int(point.get("risk", 0)) for point in trend}
    assert by_time.get("01:07") == 17
    assert by_time.get("03:07") == 39
    assert by_time.get("05:07") == 64


def test_dashboard_charts_attack_vectors_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    vectors = payload.get("attackVectors", [])
    assert isinstance(vectors, list)
    for item in vectors:
        assert "name" in item
        assert "count" in item
        assert isinstance(item["count"], int)


def test_dashboard_charts_attack_vectors_active_branch(monkeypatch, client):
    async def _fake_latest_violations_and_score(_db):
        return ([], 0)

    monkeypatch.setattr("routes.api._latest_violations_and_score", _fake_latest_violations_and_score)

    username = f"attack_vec_{uuid.uuid4().hex[:8]}"
    asyncio.run(_ensure_user(username, "ADMIN"))
    asyncio.run(
        _seed_audit_actions_for_user(
            username,
            [
                "vector_bruteforce",
                "vector_bruteforce",
                "vector_bruteforce",
                "vector_credential_stuffing",
                "vector_credential_stuffing",
            ],
        )
    )

    admin_token = create_access_token({"sub": username, "role": "ADMIN"})
    response = client.get("/api/dashboard/charts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    vectors = payload.get("attackVectors", [])
    by_name = {v.get("name"): int(v.get("count", 0)) for v in vectors}
    assert by_name.get("vector_bruteforce", 0) >= 3
    assert any(name.startswith("vector_credential_stuff") and count >= 2 for name, count in by_name.items())


def test_dashboard_overview_kpi_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/overview", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert "score" in payload
    assert "trend" in payload
    assert "scannedResources" in payload
    assert "openVulnerabilities" in payload
    assert "remediatedToday" in payload
    assert payload.get("systemStatus") in ("Stable", "Monitoring", "At Risk")
    assert "lastScanTime" in payload


def test_dashboard_overview_kpi_populated_branch(monkeypatch, client):
    async def _fake_latest_violations_and_score(_db):
        return (
            [{"severity": "HIGH", "resource": f"res-{i}"} for i in range(10)],
            88,
        )

    monkeypatch.setattr("routes.api._latest_violations_and_score", _fake_latest_violations_and_score)

    prefix = f"overview-{uuid.uuid4().hex[:8]}"
    asyncio.run(_seed_config_history_rows([f"{prefix}-aws"]))

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/overview", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert int(payload.get("openVulnerabilities", 0)) >= 10
    assert payload.get("systemStatus") == "At Risk"
    assert payload.get("lastScanTime") is not None


def test_dashboard_ai_intel_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/ai-intel", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert "modelConfidence" in payload
    assert "inferenceLatencyMs" in payload
    assert "anomaliesBlocked" in payload
    assert isinstance(payload.get("anomaliesBlocked"), int)
    assert "liveStream" in payload and isinstance(payload.get("liveStream"), list)


def test_dashboard_ai_intel_active_threats_branch(monkeypatch, client):
    async def _fake_dashboard_behavior(_db):
        return {
            "score": 86,
            "status": "Critical",
            "insights": ["policy_delete_attempt", "failed_login_spike"],
            "timeline": [
                {"action": "policy_delete_attempt", "service": "audit", "timestamp": "2026-01-01T10:11:12"},
                {"action": "failed_login_spike", "service": "auth", "timestamp": "2026-01-01T10:12:13"},
            ],
            "risk_evolution": [],
            "heatmap": {str(i): 0 for i in range(24)},
            "anomalies": [
                {"user": "u1", "action": "policy_delete_attempt", "score": 92, "time": "2026-01-01T10:11:12"},
                {"user": "u2", "action": "failed_login_spike", "score": 88, "time": "2026-01-01T10:12:13"},
                {"user": "u3", "action": "iam_policy_change", "score": 82, "time": "2026-01-01T10:13:14"},
            ],
        }

    monkeypatch.setattr("routes.api.dashboard_behavior", _fake_dashboard_behavior)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/ai-intel", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert int(payload.get("anomaliesBlocked", 0)) == 3
    assert len(payload.get("liveStream", [])) >= 2
    assert any(int(row.get("riskScore", 0)) >= 80 for row in payload.get("liveStream", []))


def test_dashboard_ai_intel_stream_action_thresholds(monkeypatch, client):
    async def _fake_dashboard_behavior(_db):
        return {
            "score": 45,
            "status": "Suspicious",
            "insights": [],
            "timeline": [
                {"action": "evt-1", "service": "audit", "timestamp": "2026-01-01T10:10:11"},
                {"action": "evt-2", "service": "audit", "timestamp": "2026-01-01T10:10:12"},
                {"action": "evt-3", "service": "audit", "timestamp": "2026-01-01T10:10:13"},
            ],
            "risk_evolution": [],
            "heatmap": {str(i): 0 for i in range(24)},
            "anomalies": [{"user": "u", "action": "evt-1", "score": 70, "time": "2026-01-01T10:10:11"}],
        }

    monkeypatch.setattr("routes.api.dashboard_behavior", _fake_dashboard_behavior)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/ai-intel", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    stream = payload.get("liveStream", [])
    assert len(stream) == 3
    assert stream[0]["riskScore"] == 45
    assert stream[0]["action"] == "FLAG FOR REVIEW"
    assert stream[0]["time"] == "10:10:11"


def test_dashboard_ai_intel_stream_max_rows(monkeypatch, client):
    async def _fake_dashboard_behavior(_db):
        timeline = []
        for i in range(12):
            timeline.append(
                {"action": f"evt-{i}", "service": "audit", "timestamp": f"2026-01-01T10:10:{i:02d}"}
            )
        return {
            "score": 20,
            "status": "Suspicious",
            "insights": [],
            "timeline": timeline,
            "risk_evolution": [],
            "heatmap": {str(i): 0 for i in range(24)},
            "anomalies": [],
        }

    monkeypatch.setattr("routes.api.dashboard_behavior", _fake_dashboard_behavior)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/ai-intel", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    stream = payload.get("liveStream", [])
    assert len(stream) == 10


def test_dashboard_ai_intel_auto_remediate_threshold_boundary(monkeypatch, client):
    async def _fake_dashboard_behavior(_db):
        return {
            "score": 80,
            "status": "Critical",
            "insights": [],
            "timeline": [
                {"action": "evt-80", "service": "audit", "timestamp": "2026-01-01T10:10:11"},
            ],
            "risk_evolution": [],
            "heatmap": {str(i): 0 for i in range(24)},
            "anomalies": [{"user": "u", "action": "evt-80", "score": 80, "time": "2026-01-01T10:10:11"}],
        }

    monkeypatch.setattr("routes.api.dashboard_behavior", _fake_dashboard_behavior)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/ai-intel", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    stream = payload.get("liveStream", [])
    assert len(stream) == 1
    assert stream[0]["riskScore"] == 80
    assert stream[0]["action"] == "AUTO-REMEDIATE"


def test_dashboard_ai_intel_does_not_execute_remediation(monkeypatch, client):
    async def _fake_dashboard_behavior(_db):
        return {
            "score": 95,
            "status": "Critical",
            "insights": [],
            "timeline": [
                {"action": "evt-hi", "service": "audit", "timestamp": "2026-01-01T10:10:11"},
            ],
            "risk_evolution": [],
            "heatmap": {str(i): 0 for i in range(24)},
            "anomalies": [{"user": "u", "action": "evt-hi", "score": 95, "time": "2026-01-01T10:10:11"}],
        }

    class _GuardTask:
        @staticmethod
        def delay(*_args, **_kwargs):
            raise AssertionError("run_remediation_task.delay must not be called by /dashboard/ai-intel")

    monkeypatch.setattr("routes.api.dashboard_behavior", _fake_dashboard_behavior)
    monkeypatch.setattr("routes.api.run_remediation_task", _GuardTask)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/dashboard/ai-intel", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    stream = payload.get("liveStream", [])
    assert len(stream) == 1
    assert stream[0]["action"] == "AUTO-REMEDIATE"


def test_rollback_fix_admin_only(client):
    user_token = _create_token_with_user("USER")
    response = client.post(
        "/api/rollback-fix/resource-1",
        headers=_auth_header(user_token),
        params={"action": "close_ports"},
    )
    assert response.status_code == 403


def test_rollback_fix_success(monkeypatch, client):
    def _ok(*_args, **_kwargs):
        return True

    monkeypatch.setattr("routes.api.rollback_engine.undo_single_fix", _ok)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/rollback-fix/resource-1",
        headers=_auth_header(admin_token),
        params={"action": "close_ports"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"


def test_rollback_fix_failure_returns_400(monkeypatch, client):
    def _fail(*_args, **_kwargs):
        return False

    monkeypatch.setattr("routes.api.rollback_engine.undo_single_fix", _fail)

    admin_token = _create_token_with_user("ADMIN")
    response = client.post(
        "/api/rollback-fix/resource-1",
        headers=_auth_header(admin_token),
        params={"action": "unsupported_action"},
    )
    assert response.status_code == 400


def test_rules_engine_evaluator_detects_multiple_violation_types():
    config = {
        "s3_buckets": {
            "public-bucket": {"public_access_block": False},
        },
        "iam_roles": {
            "admin-role": {"is_admin": True},
        },
        "security_groups": {
            "sg-1": {
                "open_ports": ["0.0.0.0/0"],
                "ip_permissions": [],
            }
        },
        "iam_users": {
            "alice": {"mfa_enabled": False},
        },
        "databases": {
            "db1": {"encrypted": False, "publicly_accessible": True},
        },
    }

    result = RuleEvaluator.evaluate("aws", config)
    violations = result.get("violations", [])
    assert len(violations) >= 5
    rule_ids = {v.get("rule_id") for v in violations}
    assert "S3_PUBLIC_ACCESS" in rule_ids
    assert "IAM_ADMIN_PRIVILEGES" in rule_ids
    assert "NETWORK_OPEN_PORTS" in rule_ids
    assert "IAM_NO_MFA" in rule_ids
    assert result.get("risk_score", 0) > 0


def test_rules_engine_risk_score_caps_and_handles_unknown_severity():
    violations = [
        {"severity": "CRITICAL"},
        {"severity": "CRITICAL"},
        {"severity": "UNKNOWN_LEVEL"},
    ]
    score = calculate_risk_score(violations)
    assert score == 100


def test_alerts_endpoint_active_rules_branch(monkeypatch, client):
    prefix = f"rules-{uuid.uuid4().hex[:8]}"
    asyncio.run(_seed_config_history_rows([f"{prefix}-aws"]))

    def _fake_evaluate(_platform, _config):
        return {
            "risk_score": 91,
            "violations": [
                {
                    "resource": "s3://prod-public",
                    "description": "S3 bucket is publicly accessible",
                    "severity": "CRITICAL",
                },
                {
                    "resource": "IAM Role: admin-role",
                    "description": "Admin privileges detected",
                    "severity": "HIGH",
                },
            ],
        }

    monkeypatch.setattr("services.rules_engine.evaluator.RuleEvaluator.evaluate", _fake_evaluate)

    admin_token = _create_token_with_user("ADMIN")
    response = client.get("/api/alerts", headers=_auth_header(admin_token))
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 2
    assert payload[0]["status"] == "Open"
    assert int(payload[0]["riskScore"]) == 91
    assert payload[0]["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_ml_model_safe_vs_risky_separation():
    safe_features = {
        "public_access": "false",
        "permission_level": 1,
        "firewall_exposure": 0,
        "encryption_status": "enabled",
        "database_access": "private",
        "number_of_changes": 0,
        "IAM_modification_frequency": 0,
        "resource_creation_rate": 1,
        "storage_access_rate": 2,
        "unusual_location_access": "false",
        "API_request_frequency": 20,
        "privilege_escalation_attempt": "false",
    }
    risky_features = {
        "public_access": "true",
        "permission_level": 9,
        "firewall_exposure": 4,
        "encryption_status": "disabled",
        "database_access": "public",
        "number_of_changes": 8,
        "IAM_modification_frequency": 6,
        "resource_creation_rate": 30,
        "storage_access_rate": 600,
        "unusual_location_access": "true",
        "API_request_frequency": 4000,
        "privilege_escalation_attempt": "true",
    }

    safe = ml_runtime_engine.predict(safe_features)
    risky = ml_runtime_engine.predict(risky_features)
    assert int(risky.get("risk_score", 0)) > int(safe.get("risk_score", 0))
    assert safe.get("prediction") in ("SAFE", "RISK")
    assert risky.get("prediction") in ("RISK", "CRITICAL")


def test_ml_model_extreme_profile_escalates_to_critical():
    extreme = {
        "public_access": "true",
        "permission_level": 10,
        "firewall_exposure": 5,
        "encryption_status": "disabled",
        "database_access": "public",
        "number_of_changes": 20,
        "IAM_modification_frequency": 10,
        "resource_creation_rate": 80,
        "storage_access_rate": 1200,
        "unusual_location_access": "true",
        "API_request_frequency": 10000,
        "privilege_escalation_attempt": "true",
    }

    out = ml_runtime_engine.predict(extreme)
    assert int(out.get("risk_score", 0)) >= 80
    assert out.get("prediction") == "CRITICAL"


def test_create_baseline_endpoint_versions_increment(client):
    admin_token = _create_token_with_user("ADMIN")
    account_id = f"baseline-{uuid.uuid4().hex[:8]}"

    first = client.post(
        "/api/create-baseline",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": True}
                }
            },
        },
    )
    assert first.status_code == 200
    assert first.json().get("version") == 1

    second = client.post(
        "/api/create-baseline",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": True},
                    "bucket-b": {"public_access_block": True},
                }
            },
        },
    )
    assert second.status_code == 200
    assert second.json().get("version") == 2


def test_compare_config_needs_baseline_branch(client):
    admin_token = _create_token_with_user("ADMIN")
    account_id = f"cmp-nobase-{uuid.uuid4().hex[:8]}"

    response = client.post(
        "/api/compare-config",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "current_configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": True}
                }
            },
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("needs_baseline") is True
    assert payload.get("drift_detected") is False
    assert isinstance(payload.get("risk_data", {}).get("risk_score"), int)
    assert isinstance(payload.get("violations"), list)


def test_compare_config_drift_detection_branch(client):
    admin_token = _create_token_with_user("ADMIN")
    account_id = f"cmp-drift-{uuid.uuid4().hex[:8]}"

    baseline_resp = client.post(
        "/api/create-baseline",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": True}
                }
            },
        },
    )
    assert baseline_resp.status_code == 200

    compare_resp = client.post(
        "/api/compare-config",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "current_configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": False}
                }
            },
        },
    )
    assert compare_resp.status_code == 200
    payload = compare_resp.json()
    assert payload.get("needs_baseline") is False
    assert payload.get("drift_detected") is True
    assert isinstance(payload.get("changes"), list)
    assert len(payload.get("changes")) >= 1
    assert isinstance(payload.get("behavior_analysis"), dict)


def test_compare_config_behavior_analysis_contract(client):
    admin_token = _create_token_with_user("ADMIN")
    account_id = f"cmp-beh-contract-{uuid.uuid4().hex[:8]}"

    response = client.post(
        "/api/compare-config",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "current_configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": True}
                },
                "user_activity": {
                    "action": "config_change",
                    "service": "S3",
                    "location": "ap-south-1",
                    "timestamp": "2026-01-01T12:10:11+00:00",
                },
            },
        },
    )
    assert response.status_code == 200
    payload = response.json()
    behavior = payload.get("behavior_analysis", {})
    assert isinstance(behavior.get("score"), int)
    assert behavior.get("status") in ("Normal", "Suspicious", "Critical")
    assert isinstance(behavior.get("insights"), list)
    assert isinstance(behavior.get("timeline"), list)
    assert isinstance(behavior.get("risk_evolution"), list)
    assert isinstance(behavior.get("heatmap"), dict)


def test_compare_config_behavior_analysis_status_mapping(monkeypatch, client):
    admin_token = _create_token_with_user("ADMIN")
    account_id = f"cmp-beh-status-{uuid.uuid4().hex[:8]}"

    client.post(
        "/api/create-baseline",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": True}
                }
            },
        },
    )

    def _fake_track_activity(*_args, **_kwargs):
        return 75, ["Synthetic suspicious behavior"], {
            "timeline": [{"action": "config_change", "timestamp": "2026-01-01T00:00:00+00:00"}],
            "risk_evolution": [{"timestamp": "2026-01-01T00:00:00+00:00", "score": 75}],
            "heatmap": {str(i): 0 for i in range(24)},
        }

    monkeypatch.setattr("services.baseline_service.behavior_engine.track_activity", _fake_track_activity)

    response = client.post(
        "/api/compare-config",
        headers=_auth_header(admin_token),
        json={
            "platform": "aws",
            "account_id": account_id,
            "current_configuration": {
                "s3_buckets": {
                    "bucket-a": {"public_access_block": False}
                }
            },
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("behavior_analysis", {}).get("status") == "Critical"
    assert int(payload.get("behavior_analysis", {}).get("score", 0)) == 75
