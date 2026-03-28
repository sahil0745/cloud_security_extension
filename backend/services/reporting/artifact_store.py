import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
import jwt
from cryptography.fernet import Fernet

from auth.security import SECRET_KEY, ALGORITHM


class ReportArtifactStore:
    def __init__(self):
        base_dir = os.getenv("REPORT_ARTIFACT_DIR", "./report_artifacts")
        self.base_path = Path(base_dir)
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Fernet key should be 32 url-safe base64-encoded bytes.
        encryption_key = os.getenv("REPORT_ENCRYPTION_KEY", "")
        if not encryption_key:
            encryption_key = Fernet.generate_key().decode("utf-8")
            os.environ["REPORT_ENCRYPTION_KEY"] = encryption_key
        self.fernet = Fernet(encryption_key.encode("utf-8"))

    def store_encrypted(
        self,
        content: bytes,
        extension: str,
        ttl_minutes: int = 30,
        requested_by: str | None = None,
    ) -> Dict[str, Any]:
        artifact_id = f"report-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        encrypted = self.fernet.encrypt(content)
        path = self.base_path / f"{artifact_id}.{extension}.enc"
        path.write_bytes(encrypted)

        exp = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        token = jwt.encode(
            {
                "typ": "report_download",
                "artifact_id": artifact_id,
                "extension": extension,
                "requested_by": requested_by,
                "exp": exp,
            },
            SECRET_KEY,
            algorithm=ALGORITHM,
        )

        return {
            "artifact_id": artifact_id,
            "extension": extension,
            "expires_at": exp.isoformat(),
            "token": token,
        }

    def load_decrypted(self, artifact_id: str, extension: str) -> bytes:
        path = self.base_path / f"{artifact_id}.{extension}.enc"
        encrypted = path.read_bytes()
        return self.fernet.decrypt(encrypted)

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("typ") != "report_download":
            raise ValueError("Invalid token type")
        return payload


artifact_store = ReportArtifactStore()
