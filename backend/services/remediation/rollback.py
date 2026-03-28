from typing import Dict, Any
import structlog
from services.remediation.actions import cloud_actions

logger = structlog.get_logger()

class RollbackSystem:
    @staticmethod
    def rollback_to_baseline(resource_id: str, baseline_snapshot: Dict[str, Any]) -> bool:
        """Uses baseline module to restore previous configuration and revert unsafe changes."""
        logger.info(
            "critical_rollback_started",
            resource_id=resource_id,
            baseline_version=baseline_snapshot.get("version", "latest")
        )

        rollback_actions = baseline_snapshot.get("rollback_actions", [])
        if not rollback_actions:
            logger.warning("rollback_actions_missing", resource_id=resource_id)
            return False

        all_success = True
        for action in rollback_actions:
            action_type = str(action.get("type", "")).lower()
            target = action.get("resource_id", resource_id)

            if action_type in {"block_public", "storage_private"}:
                ok = cloud_actions.fix_storage_public_access(target)
            elif action_type in {"restrict_iam", "remove_admin_policy"}:
                ok = cloud_actions.restrict_iam_wildcard(target)
            elif action_type in {"close_ports", "network_restrict"}:
                ok = cloud_actions.close_open_ports(target)
            elif action_type in {"enable_encryption", "encrypt"}:
                ok = cloud_actions.enforce_encryption(target)
            else:
                logger.warning("rollback_action_unknown", action_type=action_type, resource_id=target)
                ok = False

            all_success = all_success and ok

        return all_success

    @staticmethod
    def undo_single_fix(resource_id: str, action: str) -> bool:
        """(UX Upgrade) Reverts a specific isolated remediation action without full baseline restoration."""
        logger.info("single_fix_undo_started", resource_id=resource_id, action=action)

        normalized = (action or "").lower()
        if "public" in normalized or "storage" in normalized:
            return cloud_actions.fix_storage_public_access(resource_id)
        if "iam" in normalized or "wildcard" in normalized:
            return cloud_actions.restrict_iam_wildcard(resource_id)
        if "port" in normalized or "network" in normalized:
            return cloud_actions.close_open_ports(resource_id)
        if "encrypt" in normalized:
            return cloud_actions.enforce_encryption(resource_id)

        logger.warning("undo_single_fix_unknown_action", resource_id=resource_id, action=action)
        return False

rollback_engine = RollbackSystem()
