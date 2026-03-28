import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import time
import os
import structlog
from typing import List, Dict, Any

logger = structlog.get_logger()

class CloudSecurityMLEngine:
    def __init__(self, model_path="cloud_sec_model.joblib", anomaly_model_path="anomaly_model.joblib"):
        self.model_path = model_path
        self.anomaly_model_path = anomaly_model_path
        self.classifier_pipeline = None
        self.anomaly_pipeline = None
        
        # Define feature groups
        self.categorical_features = [
            'public_access', 'encryption_status', 'database_access', 'unusual_location_access', 'privilege_escalation_attempt'
        ]
        self.numeric_features = [
            'permission_level', 'firewall_exposure', 'number_of_changes',
            'IAM_modification_frequency', 'resource_creation_rate',
            'storage_access_rate', 'API_request_frequency'
        ]

    def _build_preprocessor(self):
        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])

        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])

        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, self.numeric_features),
                ('cat', categorical_transformer, self.categorical_features)
            ])
        return preprocessor

    def train_models(self, df: pd.DataFrame, labels: pd.Series):
        logger.info("Starting model training pipeline...")
        if len(df) < 10:
            logger.warning("ml_training_skipped_insufficient_data", rows=len(df))
            return False
        
        X_train, X_test, y_train, y_test = train_test_split(df, labels, test_size=0.2, random_state=42)
        
        preprocessor = self._build_preprocessor()
        
        # 1. Train Anomaly Detector (Isolation Forest)
        logger.info("Training Isolation Forest for anomaly detection...")
        self.anomaly_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('model', IsolationForest(n_estimators=100, contamination=0.05, random_state=42))
        ])
        self.anomaly_pipeline.fit(X_train)
        
        # 2. Train Classifier (Random Forest)
        logger.info("Training Random Forest Classifier...")
        rf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
        
        self.classifier_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('model', rf)
        ])
        
        self.classifier_pipeline.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.classifier_pipeline.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        logger.info(f"Classifier Accuracy: {acc:.4f}")
        
        # Save models
        joblib.dump(self.classifier_pipeline, self.model_path)
        joblib.dump(self.anomaly_pipeline, self.anomaly_model_path)
        logger.info("Models saved successfully.")
        return True

    def _audit_logs_to_dataset(self, audit_logs: List[Any]):
        data = []
        labels = []

        for log in audit_logs:
            action_str = str(getattr(log, "action", "")).lower()
            res_str = str(getattr(log, "resource", "")).lower()
            status_str = str(getattr(log, "status", "")).lower()

            features = {
                "public_access": "true" if "public" in action_str or "public" in res_str else "false",
                "permission_level": 8 if "admin" in action_str or "privilege" in action_str else 3,
                "firewall_exposure": 3 if "network" in action_str or "port" in action_str else 0,
                "encryption_status": "disabled" if "unencrypted" in action_str or "unencrypted" in res_str else "enabled",
                "database_access": "public" if "db" in res_str or "database" in res_str else "private",
                "number_of_changes": 1,
                "IAM_modification_frequency": 1 if "iam" in action_str or "iam" in res_str else 0,
                "resource_creation_rate": 1,
                "storage_access_rate": 2 if "s3" in res_str or "bucket" in res_str else 0,
                "unusual_location_access": "false",
                "API_request_frequency": 100,
                "privilege_escalation_attempt": "true" if "denied" in status_str or "escalation" in action_str else "false"
            }

            data.append(features)
            risk = 0
            if features["public_access"] == "true":
                risk += 1
            if features["encryption_status"] == "disabled":
                risk += 1
            if features["privilege_escalation_attempt"] == "true":
                risk += 2
            labels.append(min(2, risk))

        return pd.DataFrame(data), pd.Series(labels)

    def retrain_from_audit_logs(self, audit_logs: List[Any]) -> bool:
        """Retrain from real audit log rows."""
        if len(audit_logs) < 10:
            logger.warning("Not enough real data to retrain. Need at least 10 events.")
            return False

        logger.info("ml_retraining_started", rows=len(audit_logs))
        df, labels = self._audit_logs_to_dataset(audit_logs)
        success = self.train_models(df, labels)
        if not success:
            return False
        logger.info("Successfully retrained ML model using real database events.")
        return True

    def load_models(self):
        if os.path.exists(self.model_path) and os.path.exists(self.anomaly_model_path):
            try:
                self.classifier_pipeline = joblib.load(self.model_path)
                self.anomaly_pipeline = joblib.load(self.anomaly_model_path)
                logger.info("Models loaded successfully.")
                return True
            except Exception as e:
                logger.error("ml_models_load_failed", error=str(e))
                return False
        return False

    def predict(self, features: dict):
        start_time = time.time()

        def _is_true(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value != 0
            return str(value).strip().lower() in {"true", "1", "yes", "y", "on"}
        
        # Fill missing features with defaults
        for cat in self.categorical_features:
            if cat not in features:
                features[cat] = 'false'
        for num in self.numeric_features:
            if num not in features:
                features[num] = 0

        df = pd.DataFrame([features])
        
        # 1. Anomaly Detection
        anomaly_pred = self.anomaly_pipeline.predict(df)[0]
        is_anomaly = anomaly_pred == -1
        
        anomaly_score_raw = float(self.anomaly_pipeline.decision_function(df)[0])
        # Convert raw decision function to 0..1 where higher means more anomalous.
        anomaly_score = float(1.0 / (1.0 + np.exp(8.0 * anomaly_score_raw)))
        
        # 2. Classification
        vuln_class = int(self.classifier_pipeline.predict(df)[0])
        probabilities = self.classifier_pipeline.predict_proba(df)[0]
        confidence = float(max(probabilities))

        # Use expected severity from class probabilities for smoother risk behavior.
        class_levels = np.arange(len(probabilities), dtype=float)
        expected_severity = float(np.dot(class_levels, probabilities) / max(1.0, (len(probabilities) - 1)))
        
        # 3. Risk Scoring Engine
        heuristic_score = 0.0
        if _is_true(features.get('public_access', 'false')):
            heuristic_score += 25
        if str(features.get('encryption_status', 'enabled')).lower() == 'disabled':
            heuristic_score += 20
        if str(features.get('database_access', 'private')).lower() == 'public':
            heuristic_score += 20
        if _is_true(features.get('privilege_escalation_attempt', 'false')):
            heuristic_score += 25
        if float(features.get('firewall_exposure', 0) or 0) >= 3:
            heuristic_score += 10
        if _is_true(features.get('unusual_location_access', 'false')):
            heuristic_score += 10
        if float(features.get('permission_level', 0) or 0) >= 8:
            heuristic_score += 8
        if float(features.get('IAM_modification_frequency', 0) or 0) >= 3:
            heuristic_score += 6
        heuristic_score = min(100.0, heuristic_score)

        model_score = (expected_severity * 100.0 * 0.7) + (anomaly_score * 100.0 * 0.3)
        risk_score = (model_score * 0.55) + (heuristic_score * 0.45)
        if _is_true(features.get('public_access', 'false')):
            risk_score *= 1.08

        critical_signals = 0
        if _is_true(features.get('public_access', 'false')):
            critical_signals += 1
        if str(features.get('encryption_status', 'enabled')).lower() == 'disabled':
            critical_signals += 1
        if str(features.get('database_access', 'private')).lower() == 'public':
            critical_signals += 1
        if _is_true(features.get('privilege_escalation_attempt', 'false')):
            critical_signals += 1
        if float(features.get('firewall_exposure', 0) or 0) >= 3:
            critical_signals += 1
        if _is_true(features.get('unusual_location_access', 'false')):
            critical_signals += 1

        # Strongly critical posture should not remain in mid-risk due model uncertainty.
        if heuristic_score >= 90 and critical_signals >= 4:
            risk_score = max(risk_score, 85.0)
        elif heuristic_score >= 80 and critical_signals >= 3:
            risk_score = max(risk_score, 75.0)
        
        risk_score = max(1, min(100, int(risk_score)))
        
        if risk_score >= 80:
            prediction = "CRITICAL"
        elif risk_score >= 40:
            prediction = "RISK"
        else:
            prediction = "SAFE"
            
        important_features = []
        model = self.classifier_pipeline.named_steps.get("model") if self.classifier_pipeline else None
        preprocessor = self.classifier_pipeline.named_steps.get("preprocessor") if self.classifier_pipeline else None
        if model is not None and preprocessor is not None and hasattr(model, "feature_importances_"):
            try:
                names = preprocessor.get_feature_names_out()
                pairs = sorted(zip(names, model.feature_importances_), key=lambda x: x[1], reverse=True)
                important_features = [name for name, _ in pairs if not name.endswith("_false")][:5]
            except Exception:
                important_features = []
            
        latency_ms = (time.time() - start_time) * 1000
        
        return {
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "anomaly_score": round(anomaly_score, 2),
            "risk_score": risk_score,
            "insights": {
                "is_anomaly": bool(is_anomaly),
                "inference_time_ms": round(latency_ms, 2),
                "important_features": important_features,
                "explanation": f"Model predicted {prediction} using blended ML and security heuristics. Top signals: {', '.join(important_features) if important_features else 'none'}.",
                "model_score": round(model_score, 2),
                "heuristic_score": round(heuristic_score, 2),
            }
        }

def generate_synthetic_data(n_samples=1000):
    np.random.seed(42)
    data = {
        'public_access': np.random.choice(['true', 'false'], n_samples, p=[0.15, 0.85]),
        'permission_level': np.random.randint(1, 10, n_samples),
        'firewall_exposure': np.random.randint(0, 5, n_samples),
        'encryption_status': np.random.choice(['enabled', 'disabled'], n_samples, p=[0.8, 0.2]),
        'database_access': np.random.choice(['private', 'public'], n_samples, p=[0.9, 0.1]),
        'number_of_changes': np.random.poisson(2, n_samples),
        'IAM_modification_frequency': np.random.poisson(0.5, n_samples),
        'resource_creation_rate': np.random.exponential(10, n_samples),
        'storage_access_rate': np.random.exponential(100, n_samples),
        'unusual_location_access': np.random.choice(['true', 'false'], n_samples, p=[0.05, 0.95]),
        'API_request_frequency': np.random.exponential(500, n_samples),
        'privilege_escalation_attempt': np.random.choice(['true', 'false'], n_samples, p=[0.01, 0.99])
    }
    df = pd.DataFrame(data)
    
    labels = []
    for _, row in df.iterrows():
        risk = 0
        if row['public_access'] == 'true': risk += 1
        if row['encryption_status'] == 'disabled': risk += 1
        if row['firewall_exposure'] > 2: risk += 1
        if row['database_access'] == 'public': risk += 2
        if row['unusual_location_access'] == 'true': risk += 1
        if row['privilege_escalation_attempt'] == 'true': risk += 2
        labels.append(min(2, risk)) # 0: SAFE, 1: RISK, 2: CRITICAL
        
    return df, pd.Series(labels)

# Initialize and train model on startup if not exists
engine = CloudSecurityMLEngine()
if not engine.load_models():
    logger.info("Training initial ML models...")
    df, labels = generate_synthetic_data(5000)
    engine.train_models(df, labels)
    engine.load_models()
