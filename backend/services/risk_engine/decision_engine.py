from typing import Dict, Any

class DecisionEngine:
    @staticmethod
    def determine_action(risk_data: Dict[str, Any]) -> Dict[str, Any]:
        risk_level = risk_data.get("risk_level", "SAFE")
        
        if risk_level == "CRITICAL":
            action = "AUTO_REMEDIATION"
            recommended_action = "Immediate alert, auto-remediation, and rollback to baseline."
        elif risk_level == "HIGH":
            action = "ADMIN_APPROVAL"
            recommended_action = "Alert raised. Require admin approval to proceed."
        elif risk_level == "MEDIUM":
            action = "WARNING"
            recommended_action = "Warning: Review and fix suggested issues."
        elif risk_level == "LOW":
            action = "LOG_ONLY"
            recommended_action = "Log activity for review. No immediate action."
        else:
            action = "ALLOW"
            recommended_action = "No action required. Safe."

        # Merging with incoming risk_data for complete Output Format
        output = {
            "risk_score": risk_data.get("risk_score", 0),
            "risk_level": risk_level,
            "action": action,
            "confidence": risk_data.get("confidence", 0.0),
            "explanation": risk_data.get("explanation", "No explanation available"),
            "recommended_action": recommended_action
        }
        return output

decision_engine = DecisionEngine()
