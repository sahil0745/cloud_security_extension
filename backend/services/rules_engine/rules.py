import json
import os
from typing import Dict, Any, List

# Load rules configuration from JSON
RULES_FILE = os.path.join(os.path.dirname(__file__), "rules_config.json")

def load_rules_config() -> List[Dict]:
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

RULES_CONFIG_LIST = load_rules_config()
RULES_CONFIG = {rule["rule_id"]: rule for rule in RULES_CONFIG_LIST}

class RuleDefinitions:
    """
    Contains the actual Python logic (the 'check' functions) for each rule.
    These map to the rule_ids defined in rules_config.json.
    """
    
    @staticmethod
    def check_s3_public_access(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        buckets = config.get("s3_buckets", {})
        for bucket_name, settings in buckets.items():
            if not settings.get("public_access_block", True):
                violations.append({"resource": f"s3://{bucket_name}", "detail": "S3 bucket is public"})
        return violations

    @staticmethod
    def check_gcp_bucket_public(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        buckets = config.get("cloud_storage", {})
        for bucket_name, settings in buckets.items():
            if settings.get("public_access", False):
                violations.append({"resource": f"gs://{bucket_name}", "detail": "GCP bucket is public"})
        return violations

    @staticmethod
    def check_azure_blob_public(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        storage = config.get("storage_accounts", {})
        for account_name, settings in storage.items():
            if settings.get("public_blob_access", False):
                violations.append({"resource": f"azure_blob://{account_name}", "detail": "Azure blob is public"})
        return violations

    @staticmethod
    def check_iam_admin_privileges(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        iam = config.get("iam_roles", {})
        for role_name, settings in iam.items():
            if settings.get("is_admin", False):
                violations.append({"resource": f"IAM Role: {role_name}", "detail": "Admin privileges detected"})
        return violations

    @staticmethod
    def check_iam_wildcard_permissions(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        iam = config.get("iam_policies", {})
        for policy_name, settings in iam.items():
            permissions = settings.get("permissions", [])
            if "*" in permissions or any("*" in p for p in permissions):
                violations.append({"resource": f"IAM Policy: {policy_name}", "detail": "Wildcard permissions (*)"})
        return violations

    @staticmethod
    def check_iam_no_mfa(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        users = config.get("iam_users", {})
        for user_name, settings in users.items():
            if not settings.get("mfa_enabled", True):
                violations.append({"resource": f"IAM User: {user_name}", "detail": "No MFA enabled"})
        return violations

    @staticmethod
    def check_network_open_ports(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        sgs = config.get("security_groups", {})
        for sg_name, settings in sgs.items():
            open_ports = settings.get("open_ports", [])
            if "0.0.0.0/0" in open_ports:
                violations.append({"resource": f"Security Group: {sg_name}", "detail": "Open to 0.0.0.0/0"})

            # AWS-native permissions shape from describe_security_groups.
            for perm in settings.get("ip_permissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        violations.append({
                            "resource": f"Security Group: {sg_name}",
                            "detail": f"Port {perm.get('FromPort', 'all')}-{perm.get('ToPort', 'all')} open to 0.0.0.0/0"
                        })
        return violations

    @staticmethod
    def check_network_exposed_db(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        dbs = config.get("databases", {})
        for db_name, settings in dbs.items():
            if settings.get("publicly_accessible", False):
                violations.append({"resource": f"Database: {db_name}", "detail": "Publicly accessible"})
        return violations

    @staticmethod
    def check_network_weak_firewall(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        firewalls = config.get("firewalls", {})
        for fw_name, settings in firewalls.items():
            if settings.get("allow_all", False):
                violations.append({"resource": f"Firewall: {fw_name}", "detail": "Weak firewall rules (allow all)"})
        return violations

    @staticmethod
    def check_encryption_no_at_rest(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        storage = config.get("storage_encryption", {})
        for resource_name, settings in storage.items():
            if not settings.get("default_encryption_enabled", True):
                violations.append({"resource": f"Storage: {resource_name}", "detail": "No encryption at rest"})
        return violations

    @staticmethod
    def check_encryption_no_https(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        network = config.get("network_security", {})
        for resource_name, settings in network.items():
            if not settings.get("https_enforced", True):
                violations.append({"resource": f"Endpoint: {resource_name}", "detail": "No HTTPS enforcement"})
        return violations

    @staticmethod
    def check_db_no_encryption(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        dbs = config.get("databases", {})
        for db_name, settings in dbs.items():
            if not settings.get("encrypted", settings.get("storage_encrypted", True)):
                violations.append({"resource": f"Database: {db_name}", "detail": "No database encryption at rest"})
        return violations

    @staticmethod
    def check_iam_stale_credentials(config: Dict[str, Any]) -> List[Dict]:
        violations = []
        users = config.get("iam_users", {})
        for user_name, settings in users.items():
            key_age = settings.get("access_key_age_days")
            if isinstance(key_age, (int, float)) and key_age > 90:
                violations.append({
                    "resource": f"IAM User: {user_name}",
                    "detail": f"Access keys older than 90 days ({int(key_age)} days)"
                })
        return violations

# Mapping of rule_id to the actual Python function
RULE_FUNCTIONS = {
    "S3_PUBLIC_ACCESS": RuleDefinitions.check_s3_public_access,
    "GCP_BUCKET_PUBLIC": RuleDefinitions.check_gcp_bucket_public,
    "AZURE_BLOB_PUBLIC": RuleDefinitions.check_azure_blob_public,
    "IAM_ADMIN_PRIVILEGES": RuleDefinitions.check_iam_admin_privileges,
    "IAM_WILDCARD_PERMISSIONS": RuleDefinitions.check_iam_wildcard_permissions,
    "IAM_NO_MFA": RuleDefinitions.check_iam_no_mfa,
    "NETWORK_OPEN_PORTS": RuleDefinitions.check_network_open_ports,
    "NETWORK_EXPOSED_DB": RuleDefinitions.check_network_exposed_db,
    "NETWORK_WEAK_FIREWALL": RuleDefinitions.check_network_weak_firewall,
    "ENCRYPTION_NO_AT_REST": RuleDefinitions.check_encryption_no_at_rest,
    "ENCRYPTION_NO_HTTPS": RuleDefinitions.check_encryption_no_https,
    "DB_NO_ENCRYPTION": RuleDefinitions.check_db_no_encryption,
    "IAM_STALE_CREDENTIALS": RuleDefinitions.check_iam_stale_credentials,
}
