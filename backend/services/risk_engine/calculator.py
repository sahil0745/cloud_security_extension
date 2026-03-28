import json
import os
from typing import Dict, Any, List

class RiskCalculator:
    def __init__(self):
        self.weights = self._load_weights()

    def _load_weights(self) -> Dict[str, Any]:
        config_path = os.path.join(os.path.dirname(__file__), 'weights_config.json')
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {
                "rules": 0.30, "ml": 0.30, "behavior": 0.20, "asset": 0.20,
                "advanced": {"repeated_alert_penalty": 1.15, "multi_factor_multiplier": 1.25, "adaptive_threshold_factor": 1.0}
            }

    def calculate_rule_score(self, violations: List[Dict[str, Any]]) -> float:
        if not violations:
            return 0.0
        
        score = 0.0
        severity_weights = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
        
        for v in violations:
            score += severity_weights.get(v.get("severity", "LOW"), 25)
            
        return min(100.0, score)

    def calculate_ml_score(self, ml_prediction: Dict[str, Any]) -> float:
        if not ml_prediction:
            return 0.0
        return float(ml_prediction.get("risk_score", 0.0))

    def calculate_behavior_score(self, behavior_analysis: Dict[str, Any]) -> float:
        if not behavior_analysis:
            return 0.0
        # behavior_analysis score can be numeric scalar or dict
        if isinstance(behavior_analysis, dict):
            return float(behavior_analysis.get("score", 0.0))
        return float(behavior_analysis)

    def calculate_asset_score(self, asset_context: Dict[str, Any]) -> float:
        if not asset_context:
            return 50.0 # Default medium criticality
        # Convert strings to floats if needed
        criticality_map = {"low": 25, "medium": 50, "high": 75, "critical": 100}
        score = asset_context.get("criticality_score", 50.0)
        if isinstance(score, str) and score.lower() in criticality_map:
            return criticality_map[score.lower()]
        return float(score)

    def compute_final_risk(self, violations: List[Dict[str, Any]], ml_prediction: Dict[str, Any], behavior_analysis: Dict[str, Any], asset_context: Dict[str, Any] = None) -> Dict[str, Any]:
        if asset_context is None:
            asset_context = {}
        rule_score = self.calculate_rule_score(violations)
        ml_score = self.calculate_ml_score(ml_prediction)
        behavior_score = self.calculate_behavior_score(behavior_analysis)
        asset_score = self.calculate_asset_score(asset_context)

        w_rules = self.weights.get("rules", 0.30)
        w_ml = self.weights.get("ml", 0.30)
        w_behavior = self.weights.get("behavior", 0.20)
        w_asset = self.weights.get("asset", 0.20)

        # Advanced Feature 1: Dynamic Weights based on context
        confidence = ml_prediction.get("confidence", 0.85) if ml_prediction else 0.85
        if confidence > 0.9:
            w_ml += 0.1
            w_rules -= 0.05
            w_behavior -= 0.05

        if asset_score > 90:
            w_asset += 0.1
            w_rules -= 0.1

        scoring_formula = (
            w_rules * rule_score +
            w_ml * ml_score +
            w_behavior * behavior_score +
            w_asset * asset_score
        )

        # Advanced Feature 4: Multi-Factor Correlation (Combine weak signals)
        weak_signals = sum(1 for s in [rule_score, ml_score, behavior_score] if 20 < s <= 50)
        advanced_config = self.weights.get("advanced", {})
        if weak_signals >= 3:
            scoring_formula *= advanced_config.get("multi_factor_multiplier", 1.25)

        # Advanced Feature 3: Time-Based Risk
        is_repeated = False
        if asset_context and asset_context.get("repeats_in_24h", 0) > 3:
            scoring_formula *= advanced_config.get("repeated_alert_penalty", 1.15)
            is_repeated = True

        # Advanced Feature 2: Adaptive Risk Thresholds
        adaptive_factor = advanced_config.get("adaptive_threshold_factor", 1.0)
        scoring_formula *= adaptive_factor

        final_score = min(100.0, max(0.0, scoring_formula))

        # Risk Level Classification mapping
        if final_score <= 20: # 0-20 SAFE
            risk_level = "SAFE"
        elif final_score <= 40: # 21-40 LOW
            risk_level = "LOW"
        elif final_score <= 60: # 41-60 MEDIUM
            risk_level = "MEDIUM"
        elif final_score <= 80: # 61-80 HIGH
            risk_level = "HIGH"
        else: # 81-100 CRITICAL
            risk_level = "CRITICAL"

        # Explainability feature
        factors = []
        if rule_score > 50: factors.append(f"High Rule Violations ({len(violations)})")
        if ml_score > 50: factors.append("Anomalous Configuration (ML)")
        if behavior_score > 50: factors.append("Abnormal Behavior Detected")
        if asset_score > 70: factors.append("Critical Asset Exposed")
        if weak_signals >= 3: factors.append("Multiple Weak Signals Correlated")
        if is_repeated: factors.append("Repeated alerts penalty applied")

        explanation = " + ".join(factors) if factors else "Normal activity"

        return {
            "risk_score": round(final_score),
            "risk_level": risk_level,
            "confidence": round(float(confidence), 2),
            "explanation": explanation,
            "components": {
                "rule_score": round(rule_score),
                "ml_score": round(ml_score),
                "behavior_score": round(behavior_score),
                "asset_score": round(asset_score)
            }
        }

calculator = RiskCalculator()
