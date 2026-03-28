import os, sys, json
sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))
os.chdir(os.path.join(os.getcwd(), 'backend'))
from ml_engine import engine

sample_safe = {
    'public_access': 'false',
    'permission_level': 2,
    'firewall_exposure': 0,
    'encryption_status': 'enabled',
    'database_access': 'private',
    'number_of_changes': 0,
    'IAM_modification_frequency': 0,
    'resource_creation_rate': 1,
    'storage_access_rate': 2,
    'unusual_location_access': 'false',
    'API_request_frequency': 50,
    'privilege_escalation_attempt': 'false'
}

sample_risky = {
    'public_access': 'true',
    'permission_level': 9,
    'firewall_exposure': 4,
    'encryption_status': 'disabled',
    'database_access': 'public',
    'number_of_changes': 7,
    'IAM_modification_frequency': 5,
    'resource_creation_rate': 30,
    'storage_access_rate': 600,
    'unusual_location_access': 'true',
    'API_request_frequency': 1200,
    'privilege_escalation_attempt': 'true'
}

p1 = engine.predict(sample_safe)
p2 = engine.predict(sample_risky)
print('MODEL_LOAD_OK=1')
print('SAFE_PRED=' + json.dumps(p1))
print('RISKY_PRED=' + json.dumps(p2))
print('RISK_SCORE_ORDER_OK=' + str(int(p2.get('risk_score',0) >= p1.get('risk_score',0))))
