import json, os, datetime
from policy_engine.risk_engine import record_and_score

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_FILE = os.path.join(BASE, "policies", "policy.json")
REGISTRY_FILE = os.path.join(BASE, "policies", "devices.json")

def load_json(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)

def evaluate(device_id, resource, now_hour=None):
    policy = load_json(POLICY_FILE)
    registry = load_json(REGISTRY_FILE) if os.path.exists(REGISTRY_FILE) else {}
    device = registry.get(device_id)

    if device is None:
        return False, "unknown device (not in registry / no verified identity)"
    if device.get("revoked"):
        return False, "device certificate revoked (assume breach triggered)"

    if now_hour is None:
        now_hour = datetime.datetime.now().hour

    effective_trust, anomaly, request_count = record_and_score(device_id, device["trust_score"])
    if anomaly:
        return False, f"ADAPTIVE RISK ENGINE: {request_count} requests in 10s window exceeds baseline — trust reduced to {effective_trust}, access denied (continuous verification)"

    for rule in policy["rules"]:
        if rule["resource"] == resource:
            if device["device_type"] not in rule["allowed_types"]:
                return False, f"device type '{device['device_type']}' not permitted for {resource}"
            if effective_trust < rule["min_trust_score"]:
                return False, f"trust score {effective_trust} below required {rule['min_trust_score']}"
            start, end = rule["allowed_hours"]
            if not (start <= now_hour <= end):
                return False, f"outside allowed access window ({start}:00-{end}:00), now={now_hour}:00"
            return True, "access granted: identity verified, policy satisfied, least privilege enforced"

    return False, "no matching policy rule (default deny)"
