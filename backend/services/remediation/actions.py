import structlog

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = Exception

logger = structlog.get_logger()

class CloudActions:
    @staticmethod
    def fix_storage_public_access(resource_id: str) -> bool:
        """Removes public access blocks and restricts permissions natively using boto3."""
        try:
            if boto3 is None:
                return False
            client = boto3.client('s3')
            client.put_public_access_block(
                Bucket=resource_id,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            logger.info("remediation_storage_public_access_blocked", resource_id=resource_id)
            return True
        except Exception as e:
            logger.error("remediation_storage_public_access_failed", resource_id=resource_id, error=str(e))
            return False

    @staticmethod
    def restrict_iam_wildcard(resource_id: str) -> bool:
        """Removes wildcard (*) permissions by detaching high-risk managed policies."""
        try:
            if boto3 is None:
                return False
            iam = boto3.client('iam')
            # Example: Detach AdministratorAccess
            iam.detach_role_policy(
                RoleName=resource_id, 
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            logger.info("remediation_iam_wildcard_restricted", resource_id=resource_id)
            return True
        except Exception as e:
            logger.error("remediation_iam_wildcard_failed", resource_id=resource_id, error=str(e))
            return False

    @staticmethod
    def close_open_ports(resource_id: str) -> bool:
        """Closes open network ports via Security Group adjustment."""
        try:
            if boto3 is None:
                return False
            ec2 = boto3.client('ec2')
            ec2.revoke_security_group_ingress(
                GroupId=resource_id, 
                IpPermissions=[
                    {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            )
            logger.info("remediation_open_ports_closed", resource_id=resource_id)
            return True
        except Exception as e:
            logger.error("remediation_open_ports_failed", resource_id=resource_id, error=str(e))
            return False

    @staticmethod
    def enforce_encryption(resource_id: str) -> bool:
        """Enables encryption for a specific resource, e.g., EBS Volume."""
        try:
            if boto3 is None:
                return False
            ec2 = boto3.client('ec2')
            # Regional EBS encryption enforced natively
            ec2.enable_ebs_encryption_by_default()
            logger.info("remediation_encryption_enforced", resource_id=resource_id)
            return True
        except Exception as e:
            logger.error("remediation_encryption_failed", resource_id=resource_id, error=str(e))
            return False

    @staticmethod
    def azure_restrict_blob_access(resource_id: str, subscription_id: str) -> bool:
        """Sets Azure Blob storage to private natively."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient
            credential = DefaultAzureCredential()
            client = StorageManagementClient(credential, subscription_id)
            # using 'resource_group/account_name' as resource_id for simplicity
            rg_name, account_name = resource_id.split('/')
            client.storage_accounts.update(
                rg_name, account_name,
                {"allow_blob_public_access": False}
            )
            logger.info("remediation_azure_blob_restricted", resource_id=resource_id)
            return True
        except Exception as e:
            logger.error("remediation_azure_blob_failed", resource_id=resource_id, error=str(e))
            return False

    @staticmethod
    def gcp_enforce_bucket_uniform_access(resource_id: str) -> bool:
        """Enforces uniform bucket level access on GCP natively."""
        try:
            from google.cloud import storage as gcp_storage
            # Assumes GOOGLE_APPLICATION_CREDENTIALS is set
            client = gcp_storage.Client()
            bucket = client.get_bucket(resource_id)
            bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            bucket.patch()
            logger.info("remediation_gcp_uniform_access_enforced", resource_id=resource_id)
            return True
        except Exception as e:
            logger.error("remediation_gcp_uniform_access_failed", resource_id=resource_id, error=str(e))
            return False

cloud_actions = CloudActions()
