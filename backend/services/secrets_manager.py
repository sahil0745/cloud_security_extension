import os
import json
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = Exception


def get_secret_value(env_key: str, default: str = "", secret_name: str = "prod/cloudsec/secrets", secret_field: Optional[str] = None) -> str:
    """Resolve secrets from environment in DEV and AWS Secrets Manager in PROD."""
    env_value = os.getenv(env_key, "").strip()
    if env_value:
        return env_value

    if os.getenv("ENV", "DEV") != "PROD":
        return default

    if boto3 is None:
        return default

    try:
        field = secret_field or env_key
        client = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION", "us-east-1"))
        response = client.get_secret_value(SecretId=secret_name)
        secret_dict = json.loads(response.get("SecretString", "{}"))
        return str(secret_dict.get(field, default)).strip()
    except ClientError:
        return default
