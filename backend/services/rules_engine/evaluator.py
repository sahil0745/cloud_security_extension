from typing import Dict, Any, List
from services.rules_engine.rules import RULES_CONFIG_LIST, RULE_FUNCTIONS
from services.rules_engine.severity import calculate_risk_score
import structlog

logger = structlog.get_logger()

class RuleEvaluator:
    @staticmethod
    def evaluate(platform: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a cloud configuration against the loaded rules.
        Returns a dictionary containing violations and an aggregated risk score.
        """
        violations = []

        for rule in RULES_CONFIG_LIST:
            rule_id = rule.get("rule_id")
            check_function = RULE_FUNCTIONS.get(rule_id)

            if not check_function:
                continue # Skip if no implementation exists

            try:
                # Execute the rule check
                rule_violations = check_function(config)
                
                # If the rule found issues, format them and add to the list
                for v in rule_violations:
                    violations.append({
                        "rule_id": rule_id,
                        "category": rule.get("category"),
                        "description": rule.get("description"),
                        "severity": rule.get("severity"),
                        "resource": v.get("resource", "Unknown"),
                        "detail": v.get("detail", ""),
                        "remediation": rule.get("remediation"),
                        "explanation": f"Rule {rule_id} triggered because the resource matched the misconfiguration pattern."
                    })
            except Exception as e:
                # Log error but continue evaluating other rules.
                logger.error("rule_evaluation_failed", rule_id=rule_id, error=str(e))

        risk_score = calculate_risk_score(violations)

        return {
            "violations": violations,
            "risk_score": risk_score
        }
