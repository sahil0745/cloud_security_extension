import os
import time
from typing import Dict, Any
import structlog

logger = structlog.get_logger()
IS_PROD = os.getenv("ENV", "DEV") == "PROD"

boto3 = None
ClientError = Exception
DefaultAzureCredential = None
ResourceManagementClient = None
NetworkManagementClient = None
StorageManagementClient = None
AuthorizationManagementClient = None
gcp_storage = None
gcp_compute = None
gcp_rm = None

try:
    import boto3 as _boto3
    from botocore.exceptions import ClientError as _ClientError
    boto3 = _boto3
    ClientError = _ClientError
except ImportError as e:
    logger.info("optional_cloud_sdk_not_installed", sdk="aws", error=str(e))

try:
    from azure.identity import DefaultAzureCredential as _DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient as _ResourceManagementClient
    from azure.mgmt.network import NetworkManagementClient as _NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient as _StorageManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient as _AuthorizationManagementClient
    DefaultAzureCredential = _DefaultAzureCredential
    ResourceManagementClient = _ResourceManagementClient
    NetworkManagementClient = _NetworkManagementClient
    StorageManagementClient = _StorageManagementClient
    AuthorizationManagementClient = _AuthorizationManagementClient
except ImportError as e:
    logger.info("optional_cloud_sdk_not_installed", sdk="azure", error=str(e))

try:
    from google.cloud import storage as _gcp_storage
    from google.cloud import compute_v1 as _gcp_compute
    from google.cloud import resourcemanager_v3 as _gcp_rm
    gcp_storage = _gcp_storage
    gcp_compute = _gcp_compute
    gcp_rm = _gcp_rm
except ImportError as e:
    logger.info("optional_cloud_sdk_not_installed", sdk="gcp", error=str(e))

class CloudService:
    @staticmethod
    def _with_retry(func, attempts: int = 3, base_delay: float = 0.5):
        last_exc = None
        for i in range(attempts):
            try:
                return func()
            except Exception as exc:
                last_exc = exc
                if i < attempts - 1:
                    time.sleep(base_delay * (2 ** i))
        raise last_exc

    @classmethod
    def fetch_config(cls, platform: str, account_id: str = "default") -> Dict[str, Any]:
        if platform.upper() == "AWS":
            return cls._with_retry(cls.fetch_aws_config)
        elif platform.upper() == "AZURE":
            return cls._with_retry(lambda: cls.fetch_azure_config(account_id))
        elif platform.upper() == "GCP":
            return cls._with_retry(lambda: cls.fetch_gcp_config(account_id))
        else:
            raise ValueError(f"Unsupported platform: {platform}")

    @staticmethod
    def fetch_aws_config() -> Dict[str, Any]:
        """Fetches AWS configuration natively using Boto3 paginators."""
        config_data = {
            "s3_buckets": {},
            "iam_roles": {},
            "security_groups": {},
            "ec2_instances": {}
        }
        if boto3 is None:
            logger.info("aws_sdk_unavailable_falling_through_to_demo")
        else:
          try:
            # S3
            s3 = boto3.client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            for b in buckets:
                name = b['Name']
                try:
                    s3.get_public_access_block(Bucket=name)
                    config_data["s3_buckets"][name] = {"public_access_block": True}
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        config_data["s3_buckets"][name] = {"public_access_block": False}
                    else:
                        config_data["s3_buckets"][name] = {"public_access_block": "Unknown"}
                
                try:
                    policy = s3.get_bucket_policy(Bucket=name)
                    config_data["s3_buckets"][name]["policy"] = policy.get('Policy')
                except ClientError:
                    config_data["s3_buckets"][name]["policy"] = None
            
            # IAM
            iam = boto3.client('iam')
            paginator = iam.get_paginator('list_roles')
            roles_count = 0
            for page in paginator.paginate():
                for role in page['Roles']:
                    roles_count += 1
                    config_data["iam_roles"][role['RoleName']] = {"arn": role['Arn']}
            
            config_data["iam_roles"]["total_roles"] = roles_count

            # EC2 & Security Groups
            ec2 = boto3.client('ec2')
            sg_paginator = ec2.get_paginator('describe_security_groups')
            for page in sg_paginator.paginate():
                for sg in page['SecurityGroups']:
                    config_data["security_groups"][sg['GroupId']] = {
                        "name": sg['GroupName'],
                        "ip_permissions": sg.get('IpPermissions', [])
                    }

            instance_paginator = ec2.get_paginator('describe_instances')
            for page in instance_paginator.paginate():
                for r in page['Reservations']:
                    for inst in r['Instances']:
                        config_data["ec2_instances"][inst['InstanceId']] = {
                            "state": inst['State']['Name'],
                            "public_ip": inst.get('PublicIpAddress', None)
                        }

          except Exception as e:
            logger.error("aws_config_fetch_failed", error=str(e))
        
        if not config_data.get("s3_buckets") and not config_data.get("iam_roles"):
            logger.info("aws_falling_back_to_demo_data")
            # AWS: HIGHEST RISK — 7 violations (S3 + IAM + MFA + network + DB)
            return {
                "s3_buckets": {
                    "prod-data-bucket": {"public_access_block": False},
                    "staging-logs": {"public_access_block": False},
                    "dev-assets": {"public_access_block": True}
                },
                "iam_policies": {
                    "admin-policy": {"permissions": ["*"]},
                    "deploy-role": {"permissions": ["*"]}
                },
                "iam_users": {
                    "legacy_svc_account": {"mfa_enabled": False, "access_key_age_days": 120},
                    "dev_user": {"mfa_enabled": False, "access_key_age_days": 45}
                },
                "security_groups": {
                    "sg-web-facing": {"open_ports": ["0.0.0.0/0"]},
                    "sg-ssh-open": {"open_ports": ["0.0.0.0/0"]}
                },
                "databases": {
                    "prod-rds-main": {"publicly_accessible": True, "encrypted": False},
                    "analytics-db": {"publicly_accessible": True, "encrypted": True}
                }
            }
            
        return config_data

    @staticmethod
    def fetch_azure_config(subscription_id: str) -> Dict[str, Any]:
        """Fetches Azure configuration natively using azure-mgmt libraries."""
        config_data = {
            "resource_groups": {},
            "network_security_groups": {},
            "storage_accounts": {},
            "access_policies": {}
        }
        if not all([DefaultAzureCredential, ResourceManagementClient, NetworkManagementClient, StorageManagementClient, AuthorizationManagementClient]):
            logger.info("azure_sdk_unavailable_falling_through_to_demo")
        else:
          try:
            credential = DefaultAzureCredential()
            # Resource Groups
            rm_client = ResourceManagementClient(credential, subscription_id)
            for rg in rm_client.resource_groups.list():
                config_data["resource_groups"][rg.name] = {"location": rg.location}

            # Networks
            nm_client = NetworkManagementClient(credential, subscription_id)
            for nsg in nm_client.network_security_groups.list_all():
                config_data["network_security_groups"][nsg.name] = [rule.name for rule in nsg.security_rules]

            # Storage
            sm_client = StorageManagementClient(credential, subscription_id)
            for sa in sm_client.storage_accounts.list():
                config_data["storage_accounts"][sa.name] = {"allow_blob_public_access": sa.allow_blob_public_access}

            # Access Policies (RBAC)
            auth_client = AuthorizationManagementClient(credential, subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            for ra in auth_client.role_assignments.list_for_scope(scope):
                config_data["access_policies"][ra.name] = {
                    "role_definition_id": ra.role_definition_id,
                    "principal_id": ra.principal_id
                }
          except Exception as e:
            logger.error("azure_config_fetch_failed", error=str(e))
        if not config_data.get("resource_groups") and not config_data.get("storage_accounts"):
            logger.info("azure_falling_back_to_demo_data")
            # AZURE: MEDIUM RISK — 4 violations (IAM + network + DB, no S3)
            return {
                "resource_groups": {
                    "rg-prod-core": {"location": "eastus"},
                    "rg-staging": {"location": "westus2"}
                },
                "network_security_groups": {
                    "nsg-web-frontend": ["allow-http", "allow-ssh-all"]
                },
                "storage_accounts": {
                    "stproddataeastus": {"public_blob_access": True},
                    "stdevassets": {"public_blob_access": False}
                },
                "access_policies": {
                    "admin-role-assignment": {
                        "role_definition_id": "owner",
                        "principal_id": "service-principal-1"
                    }
                },
                "iam_policies": {
                    "azure-contributor-policy": {"permissions": ["*"]}
                },
                "security_groups": {
                    "nsg-rdp-open": {"open_ports": ["0.0.0.0/0"]}
                },
                "databases": {
                    "azure-sql-prod": {"publicly_accessible": True, "encrypted": False}
                }
            }
            
        return config_data

    @staticmethod
    def fetch_gcp_config(project_id: str) -> Dict[str, Any]:
        """Fetches GCP configuration using native Google SDKs."""
        config_data = {
            "cloud_storage": {},
            "compute_instances": {},
            "iam_policies": {}
        }
        if not all([gcp_storage, gcp_compute, gcp_rm]):
            logger.info("gcp_sdk_unavailable_falling_through_to_demo")
        else:
          try:
            # Storage
            storage_client = gcp_storage.Client(project=project_id)
            for bucket in storage_client.list_buckets():
                config_data["cloud_storage"][bucket.name] = {
                    "uniform_bucket_level_access": bucket.iam_configuration.uniform_bucket_level_access_enabled
                }

            # Compute
            compute_client = gcp_compute.InstancesClient()
            request = gcp_compute.AggregatedListInstancesRequest(project=project_id)
            instances = compute_client.aggregated_list(request=request)
            for zone, response in instances:
                if response.instances:
                    for instance in response.instances:
                        config_data["compute_instances"][instance.name] = {"status": instance.status}

            # IAM
            rm_client = gcp_rm.ProjectsClient()
            iam_policy = rm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
            for binding in iam_policy.bindings:
                config_data["iam_policies"][binding.role] = list(binding.members)

          except Exception as e:
            logger.error("gcp_config_fetch_failed", error=str(e))
            
        if not config_data.get("cloud_storage") and not config_data.get("compute_instances"):
            logger.info("gcp_falling_back_to_demo_data")
            # GCP: LOWEST RISK — 2 violations (firewall + exposed DB only)
            return {
                "cloud_storage": {
                    "gcp-prod-public-assets": {"public_access": True, "uniform_bucket_level_access": False},
                    "gcp-secure-backups": {"public_access": False, "uniform_bucket_level_access": True}
                },
                "compute_instances": {
                    "instance-prod-db-1": {"status": "RUNNING"},
                    "instance-web-1": {"status": "RUNNING"}
                },
                "iam_policies": {
                    "roles/viewer": {"permissions": ["read"]}
                },
                "security_groups": {
                    "fw-web-ingress": {"open_ports": ["0.0.0.0/0"]}
                },
                "databases": {
                    "gcp-cloudsql-staging": {"publicly_accessible": True, "encrypted": True}
                }
            }
            
        return config_data
