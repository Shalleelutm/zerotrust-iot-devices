import sys, os, json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(BASE, "policies", "devices.json")

def revoke(device_id):
    with open(REGISTRY) as f:
        registry = json.load(f)
    if device_id not in registry:
        print(f"Unknown device: {device_id}")
        return
    registry[device_id]["revoked"] = True
    with open(REGISTRY, "w") as f:
        json.dump(registry, f, indent=2)
    print(f"REVOKED: {device_id} (assume-breach response executed)")

if __name__ == "__main__":
    revoke(sys.argv[1])
