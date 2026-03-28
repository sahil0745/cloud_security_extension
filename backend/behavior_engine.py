import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class UserProfile:
    def __init__(self, user_id):
        self.user_id = user_id
        self.activities = []
        self.normal_services = set()
        self.usual_locations = set()
        self.avg_actions_per_day = 0
        self.action_history_dates = {} # date -> count
        self.model = IsolationForest(n_estimators=50, contamination=0.1, random_state=42)
        self.is_trained = False
        self.risk_history = [] # list of dicts: {'timestamp': str, 'score': int}

    def add_activity(self, activity, score):
        self.activities.append(activity)
        self.normal_services.add(activity.get('service', 'unknown'))
        self.usual_locations.add(activity.get('location', 'unknown'))
        
        date_str = activity.get('timestamp', _utc_now_iso())[:10]
        self.action_history_dates[date_str] = self.action_history_dates.get(date_str, 0) + 1
        
        if len(self.action_history_dates) > 0:
            self.avg_actions_per_day = sum(self.action_history_dates.values()) / len(self.action_history_dates)
            
        self.risk_history.append({
            'timestamp': activity.get('timestamp', _utc_now_iso()),
            'score': score
        })
        
        if len(self.activities) > 10:
            self.train_model()

    def get_timeline(self):
        return self.activities[-10:] # Last 10 activities

    def get_risk_evolution(self):
        return self.risk_history[-20:] # Last 20 risk scores

    def get_heatmap_data(self):
        # Hour-of-day frequency map derived from observed activity timestamps.
        heatmap = {str(i): 0 for i in range(24)}
        for a in self.activities:
            try:
                hour = datetime.fromisoformat(a.get('timestamp', _utc_now_iso())).hour
                heatmap[str(hour)] += 1
            except Exception as exc:
                logger.warning("behavior_heatmap_timestamp_parse_failed", error=str(exc))
        return heatmap

    def extract_features(self, activity):
        try:
            hour = datetime.fromisoformat(activity.get('timestamp', _utc_now_iso())).hour
        except:
            hour = 12
        is_new_location = 1 if activity.get('location') not in self.usual_locations else 0
        is_new_service = 1 if activity.get('service') not in self.normal_services else 0
        action_type_weight = 1
        if activity.get('action') in ['iam_update', 'privilege_escalation']:
            action_type_weight = 5
        elif activity.get('action') == 'config_change':
            action_type_weight = 3
            
        return [hour, is_new_location, is_new_service, action_type_weight]

    def train_model(self):
        if len(self.activities) < 5:
            return
        features = [self.extract_features(a) for a in self.activities[-100:]]
        self.model.fit(features)
        self.is_trained = True

class BehaviorEngine:
    def __init__(self):
        self.profiles = {}

    def track_activity(self, user_id, activity):
        if user_id not in self.profiles:
            self.profiles[user_id] = UserProfile(user_id)
        
        profile = self.profiles[user_id]
        score, insights = self.analyze_activity(user_id, activity)
        profile.add_activity(activity, score)
        
        advanced_data = {
            "timeline": profile.get_timeline(),
            "risk_evolution": profile.get_risk_evolution(),
            "heatmap": profile.get_heatmap_data()
        }
        
        return score, insights, advanced_data

    def analyze_activity(self, user_id, activity):
        if user_id not in self.profiles:
            return 0, ["New user, establishing baseline."]
            
        profile = self.profiles[user_id]
        score = 0
        insights = []
        
        try:
            hour = datetime.fromisoformat(activity.get('timestamp', _utc_now_iso())).hour
        except:
            hour = 12
            
        if hour < 5 or hour > 23:
            score += 30
            insights.append("Unusual access time (late night/early morning).")
            
        if activity.get('location') and activity.get('location') not in profile.usual_locations and len(profile.usual_locations) > 0:
            score += 40
            insights.append(f"Login from new location: {activity.get('location')}.")
            
        if activity.get('service') and activity.get('service') not in profile.normal_services and len(profile.normal_services) > 0:
            score += 20
            insights.append(f"Accessing unusual service: {activity.get('service')}.")
            
        date_str = activity.get('timestamp', _utc_now_iso())[:10]
        today_actions = profile.action_history_dates.get(date_str, 0)
        if profile.avg_actions_per_day > 5 and today_actions > profile.avg_actions_per_day * 3:
            score += 40
            insights.append("Abnormal spike in activity volume.")
            
        if profile.is_trained:
            features = [profile.extract_features(activity)]
            anomaly_pred = profile.model.predict(features)[0]
            if anomaly_pred == -1:
                score += 50
                insights.append("ML Model detected anomalous behavior pattern.")
                
        # Insider Threat Detection
        if activity.get('action') == 'privilege_escalation' and activity.get('location') in profile.usual_locations:
            score += 60
            insights.append("Potential Insider Threat: Privilege escalation from known location.")
            
        if profile.avg_actions_per_day > 10 and activity.get('action') == 'data_exfiltration':
            score += 80
            insights.append("Critical: Possible data exfiltration detected.")

        score = min(100, score)
        return score, insights

engine = BehaviorEngine()
