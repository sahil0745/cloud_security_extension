import os, sys, json, random
sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))
os.chdir(os.path.join(os.getcwd(), 'backend'))
from ml_engine import engine

def safe_sample():
    return {
        'public_access': 'false',
        'permission_level': random.randint(1, 4),
        'firewall_exposure': random.randint(0, 1),
        'encryption_status': 'enabled',
        'database_access': 'private',
        'number_of_changes': random.randint(0, 2),
        'IAM_modification_frequency': random.randint(0, 1),
        'resource_creation_rate': random.randint(0, 5),
        'storage_access_rate': random.randint(1, 30),
        'unusual_location_access': 'false',
        'API_request_frequency': random.randint(10, 120),
        'privilege_escalation_attempt': 'false'
    }

def risky_sample():
    return {
        'public_access': 'true',
        'permission_level': random.randint(8, 10),
        'firewall_exposure': random.randint(3, 4),
        'encryption_status': 'disabled',
        'database_access': 'public',
        'number_of_changes': random.randint(4, 10),
        'IAM_modification_frequency': random.randint(3, 7),
        'resource_creation_rate': random.randint(20, 60),
        'storage_access_rate': random.randint(250, 900),
        'unusual_location_access': 'true',
        'API_request_frequency': random.randint(700, 2000),
        'privilege_escalation_attempt': 'true'
    }

safe_scores = [engine.predict(safe_sample())['risk_score'] for _ in range(30)]
risky_scores = [engine.predict(risky_sample())['risk_score'] for _ in range(30)]
print('SAFE_AVG=' + str(round(sum(safe_scores)/len(safe_scores),2)))
print('RISKY_AVG=' + str(round(sum(risky_scores)/len(risky_scores),2)))
print('SAFE_MAX=' + str(max(safe_scores)))
print('RISKY_MIN=' + str(min(risky_scores)))
print('SEPARATION_OK=' + str(int((sum(risky_scores)/len(risky_scores)) > (sum(safe_scores)/len(safe_scores)))))
