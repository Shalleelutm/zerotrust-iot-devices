import json, os, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(BASE, "policies", "risk_state.json")
WINDOW_SECONDS = 10
MAX_REQUESTS_PER_WINDOW = 4
RISK_PENALTY = 0.5

def _load():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, encoding="utf-8-sig") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def _save(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def record_and_score(device_id, base_trust_score):
    state = _load()
    now = time.time()
    history = [t for t in state.get(device_id, []) if now - t <= WINDOW_SECONDS]
    history.append(now)
    state[device_id] = history
    _save(state)

    request_count = len(history)
    if request_count > MAX_REQUESTS_PER_WINDOW:
        return max(0.0, base_trust_score - RISK_PENALTY), True, request_count
    return base_trust_score, False, request_count
