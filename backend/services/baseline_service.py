from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models.models import Baseline, ConfigHistory
from typing import Dict, Any, Tuple, List
from services.rules_engine.evaluator import RuleEvaluator
from ml_engine import engine as ml_engine
from behavior_engine import engine as behavior_engine
from datetime import datetime, timezone
import asyncio
import json
import structlog
from services.redis_cache import redis_cache

logger = structlog.get_logger()

class BaselineService:
    @staticmethod
    def _normalize_config(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}

    @staticmethod
    async def create_baseline(db: AsyncSession, platform: str, account_id: str, config: Dict[str, Any]) -> Baseline:
        # Check for existing baseline to increment version
        result = await db.execute(
            select(Baseline).filter(
                Baseline.platform == platform, 
                Baseline.account_id == account_id
            ).order_by(Baseline.version.desc())
        )
        existing = result.scalars().first()
        
        version = (existing.version + 1) if existing else 1
        
        new_baseline = Baseline(
            platform=platform,
            account_id=account_id,
            configuration=config,
            version=version
        )
        db.add(new_baseline)
        await db.commit()
        await db.refresh(new_baseline)
        logger.info("baseline_created", platform=platform, version=version)
        return new_baseline

    @staticmethod
    async def compare_config(db: AsyncSession, platform: str, account_id: str, current_config: Dict[str, Any]) -> Tuple[bool, bool, List[Dict], int, Dict[str, Any] | None, List[Dict], Dict]:
        """
        Compares current config against the latest baseline and evaluates rules.
        Returns: (needs_baseline, drift_detected, changes, risk_score, violations, behavior_analysis)
        """
        normalized_current = BaselineService._normalize_config(current_config)

        # Step 1: Evaluate current configuration against CIS Rules Engine in worker thread.
        evaluation_result = await asyncio.to_thread(RuleEvaluator.evaluate, platform, normalized_current)
        violations = evaluation_result.get("violations", [])
        rule_score = evaluation_result.get("risk_score", 0)

        # Step 1.5: ML Prediction
        ml_features = {
            'public_access': 'true' if any(v.get('public_access_block') is False for _, v in normalized_current.get('s3_buckets', {}).items()) else 'false',
            'permission_level': 5,
            'firewall_exposure': 2,
            'encryption_status': 'enabled',
            'database_access': 'private',
            'number_of_changes': 1,
            'IAM_modification_frequency': 0,
            'resource_creation_rate': 1,
            'storage_access_rate': 10,
            'unusual_location_access': 'false',
            'API_request_frequency': 100,
            'privilege_escalation_attempt': 'false'
        }
        
        try:
            ml_result = await asyncio.to_thread(ml_engine.predict, ml_features)
            ml_score = ml_result.get("risk_score", 0)
        except Exception as e:
            logger.warning("ml_prediction_failed", error=str(e))
            ml_result = None
            ml_score = 0

        # Step 1.8: Behavior Analysis
        user_activity = normalized_current.get('user_activity', {
            "action": "config_change",
            "service": "S3",
            "location": "Unknown",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        behavior_score, behavior_insights, advanced_data = await asyncio.to_thread(
            behavior_engine.track_activity, account_id, user_activity
        )
        
        behavior_status = "Normal"
        if behavior_score >= 70:
            behavior_status = "Critical"
        elif behavior_score >= 40:
            behavior_status = "Suspicious"
            
        behavior_analysis = {
            "score": behavior_score,
            "status": behavior_status,
            "insights": behavior_insights,
            "timeline": advanced_data.get("timeline", []),
            "risk_evolution": advanced_data.get("risk_evolution", []),
            "heatmap": advanced_data.get("heatmap", {})
        }

        # Final decision
        risk_score = int(round((rule_score + ml_score + behavior_score) / 3))
        if ml_score > 0:
            risk_score = max(risk_score, int(ml_score))

        # Step 2: Compare against Baseline (ASYNC)
        result = await db.execute(
            select(Baseline).filter(
                Baseline.platform == platform, 
                Baseline.account_id == account_id
            ).order_by(Baseline.version.desc())
        )
        baseline = result.scalars().first()

        if not baseline:
            return True, False, [], risk_score, ml_result, violations, behavior_analysis

        changes = []
        
        # Baseline values are transparently decrypted by EncryptedJSONType.
        base_config = BaselineService._normalize_config(baseline.configuration)
        
        # Recursive diff logic
        def diff_dicts(base: Any, current: Any, path: str = ""):
            if not isinstance(base, dict) or not isinstance(current, dict):
                if base != current:
                    changes.append({"field": path or "root", "old": base, "new": current, "type": "modified"})
                return

            for key in base:
                current_path = f"{path}.{key}" if path else key
                if key not in current:
                    changes.append({"field": current_path, "old": base[key], "new": None, "type": "removed"})
                elif isinstance(base[key], dict) and isinstance(current[key], dict):
                    diff_dicts(base[key], current[key], current_path)
                elif base[key] != current[key]:
                    changes.append({"field": current_path, "old": base[key], "new": current[key], "type": "modified"})
            
            for key in current:
                current_path = f"{path}.{key}" if path else key
                if key not in base:
                    changes.append({"field": current_path, "old": None, "new": current[key], "type": "added"})

        diff_dicts(base_config, normalized_current)
        
        drift_detected = len(changes) > 0

        if drift_detected and risk_score < 25:
            risk_score = 25
        
        # Log history
        history = ConfigHistory(
            baseline_id=baseline.id,
            platform=platform,
            configuration=normalized_current,
            drift_detected=changes if drift_detected else None
        )
        db.add(history)
        await db.commit()

        # Cache risk result for API and extension clients.
        await redis_cache.set_risk_score(
            f"{platform}:{account_id}",
            {
                "risk_score": risk_score,
                "violations": violations,
                "behavior_analysis": behavior_analysis,
                "drift_detected": drift_detected,
            },
            ttl=300,
        )

        return False, drift_detected, changes, risk_score, ml_result, violations, behavior_analysis
