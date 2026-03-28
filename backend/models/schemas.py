from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

class FetchConfigRequest(BaseModel):
    platform: str = Field(min_length=2, max_length=16)
    account_id: str = Field(default="default", min_length=1, max_length=128)

class BaselineCreateRequest(BaseModel):
    platform: str = Field(min_length=2, max_length=16)
    account_id: str = Field(default="default", min_length=1, max_length=128)
    configuration: Dict[str, Any]

class CompareConfigRequest(BaseModel):
    platform: str = Field(min_length=2, max_length=16)
    account_id: str = Field(default="default", min_length=1, max_length=128)
    current_configuration: Dict[str, Any]

class CompareResponse(BaseModel):
    needs_baseline: bool
    drift_detected: bool
    changes: Optional[List[Dict[str, Any]]] = None
    risk_data: Optional[Dict[str, Any]] = None
    ml_prediction: Optional[Dict[str, Any]] = None
    violations: Optional[List[Dict[str, Any]]] = None
    behavior_analysis: Optional[Dict[str, Any]] = None

class RiskEvaluationRequest(BaseModel):
    violations: List[Dict[str, Any]] = Field(default_factory=list)
    ml_prediction: Dict[str, Any] = Field(default_factory=dict)
    behavior_analysis: Dict[str, Any] = Field(default_factory=dict)
    asset_context: Optional[Dict[str, Any]] = None
