import os
import base64
import json
from cryptography.fernet import Fernet
from typing import Any, Dict, List, Optional
from sqlalchemy.types import TypeDecorator, Text
from services.secrets_manager import get_secret_value


def _get_secret_value(secret_name: str, key: str) -> str:
    return get_secret_value(key, default="", secret_name=secret_name, secret_field=key)

def _load_keys() -> List[bytes]:
    # Supports key rotation via comma-separated env var: AES_ENCRYPTION_KEYS=k1,k2,k3
    raw_keys = os.getenv("AES_ENCRYPTION_KEYS", "").strip()
    if raw_keys:
        keys = [k.strip().encode("utf-8") for k in raw_keys.split(",") if k.strip()]
        if keys:
            return keys

    single = os.getenv("AES_ENCRYPTION_KEY", "").strip()
    if single:
        return [single.encode("utf-8")]

    secrets_single = _get_secret_value("prod/cloudsec/secrets", "AES_ENCRYPTION_KEY")
    if secrets_single:
        return [secrets_single.encode("utf-8")]

    secrets_keys = _get_secret_value("prod/cloudsec/secrets", "AES_ENCRYPTION_KEYS")
    if secrets_keys:
        return [k.strip().encode("utf-8") for k in secrets_keys.split(",") if k.strip()]

    # Development fallback only.
    if os.getenv("ENV", "DEV") == "PROD":
        raise RuntimeError("AES_ENCRYPTION_KEY(S) must be set in PROD")
    return [Fernet.generate_key()]


_ENCRYPTION_KEYS = _load_keys()
_CIPHERS = [Fernet(k) for k in _ENCRYPTION_KEYS]
_ACTIVE_KID = "k0"


def _encrypt_raw(payload: bytes) -> str:
    token = _CIPHERS[0].encrypt(payload)
    return f"{_ACTIVE_KID}:{base64.b64encode(token).decode('utf-8')}"


def _decrypt_raw(cipher_text: str) -> bytes:
    kid: Optional[str] = None
    encoded = cipher_text
    if ":" in cipher_text:
        kid, encoded = cipher_text.split(":", 1)

    cipher_bytes = base64.b64decode(encoded.encode("utf-8"))

    if kid == _ACTIVE_KID:
        return _CIPHERS[0].decrypt(cipher_bytes)

    for c in _CIPHERS:
        try:
            return c.decrypt(cipher_bytes)
        except Exception:
            continue
    raise ValueError("Decryption failure: no configured key could decrypt payload")

class DBEncryption:
    @staticmethod
    def encrypt_json(data: Dict[str, Any]) -> str:
        """Encrypt a JSON payload with active key version metadata."""
        data_bytes = json.dumps(data).encode("utf-8")
        return _encrypt_raw(data_bytes)

    @staticmethod
    def decrypt_json(cipher_b64: str) -> Dict[str, Any]:
        """Decrypt JSON payload using active or historical key versions."""
        try:
            plain_bytes = _decrypt_raw(cipher_b64)
            return json.loads(plain_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Decryption failure: payload corrupt or key invalid. {str(e)}")

    @staticmethod
    def encrypt_text(value: str) -> str:
        return _encrypt_raw(value.encode("utf-8"))

    @staticmethod
    def decrypt_text(cipher_text: str) -> str:
        return _decrypt_raw(cipher_text).decode("utf-8")

    @staticmethod
    def rotate_payload(cipher_text: str) -> str:
        """Re-encrypt existing encrypted payload using the active key."""
        plaintext = _decrypt_raw(cipher_text)
        return _encrypt_raw(plaintext)


class EncryptedJSONType(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            return DBEncryption.encrypt_json({"value": value})
        return DBEncryption.encrypt_json(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            decoded = DBEncryption.decrypt_json(value)
            if isinstance(decoded, dict) and "value" in decoded and len(decoded) == 1:
                return decoded["value"]
            return decoded
        except Exception:
            # Backward compatibility for pre-encryption rows.
            try:
                return json.loads(value)
            except Exception:
                return value


class EncryptedTextType(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return DBEncryption.encrypt_text(str(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return DBEncryption.decrypt_text(value)
        except Exception:
            # Backward compatibility for pre-encryption rows.
            return value
