import json, os, time, datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(BASE, "policies", "risk_state.json")
REGISTRY_FILE = os.path.join(BASE, "policies", "devices.json")
INCIDENT_LOG = os.path.join(BASE, "logs", "incidents.log")
WINDOW_SECONDS = 10
MAX_REQUESTS_PER_WINDOW = 4
RISK_PENALTY = 0.5
AUTO_REVOKE_AFTER_STRIKES = 3

def _load(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8-sig") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def _save(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def _log_incident(device_id, detail):
    os.makedirs(os.path.dirname(INCIDENT_LOG), exist_ok=True)
    with open(INCIDENT_LOG, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "device_id": device_id,
            "event": "AUTO_CONTAINMENT",
            "detail": detail
        }) + "\n")

def record_and_score(device_id, base_trust_score):
    state = _load(STATE_FILE)
    now = time.time()
    history = [t for t in state.get(device_id, {}).get("hits", []) if now - t <= WINDOW_SECONDS]
    history.append(now)
    strikes = state.get(device_id, {}).get("strikes", 0)

    request_count = len(history)
    anomaly = request_count > MAX_REQUESTS_PER_WINDOW

    if anomaly:
        strikes += 1
    state[device_id] = {"hits": history, "strikes": strikes}
    _save(STATE_FILE, state)

    if anomaly and strikes >= AUTO_REVOKE_AFTER_STRIKES:
        registry = _load(REGISTRY_FILE)
        if device_id in registry and not registry[device_id].get("revoked"):
            registry[device_id]["revoked"] = True
            registry[device_id]["auto_revoked"] = True
            _save(REGISTRY_FILE, registry)
            _log_incident(device_id, f"auto-revoked after {strikes} consecutive anomaly strikes (self-healing response)")
        return 0.0, True, request_count, True

    if anomaly:
        return max(0.0, base_trust_score - RISK_PENALTY), True, request_count, False
    return base_trust_score, False, request_count, False
