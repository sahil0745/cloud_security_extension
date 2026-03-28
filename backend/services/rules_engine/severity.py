from enum import Enum

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

SEVERITY_WEIGHTS = {
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 70,
    Severity.CRITICAL: 100
}

def calculate_risk_score(violations: list) -> int:
    """
    Calculates an aggregate risk score based on violations.
    Capped at 100.
    """
    if not violations:
        return 0
        
    score = 0
    for v in violations:
        sev_str = v.get("severity", "LOW").upper()
        try:
            sev = Severity(sev_str)
        except ValueError:
            sev = Severity.LOW
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        score += weight
        
    # Cap at 100
    return min(score, 100)
