# Zero Trust Architecture for IoT Devices — Working Software Lab

## What this proves (NIST SP 800-207 tenets, implemented)
- **Verify explicitly**: every request requires a valid mTLS client certificate signed by the lab's own Root CA. No cert = hard TLS-layer rejection before any application code runs.
- **Least privilege access**: the Policy Decision Point (policy_engine/pdp.py) grants access per-resource based on device type, trust score, and time window — not blanket network access.
- **Assume breach**: policy_engine/revoke.py simulates incident response — revoking a device's trust instantly blocks it even with a cryptographically valid certificate.
- **Continuous monitoring**: every access decision (allow or deny, with reason) is logged to logs/audit.log in real time.
- **Micro-segmentation**: each API resource (/telemetry, /actuator/unlock, /admin/config) has its own independent policy rule.

## Architecture
- ca/ — local Root Certificate Authority, issues per-device X.509 identity certificates
- gateway/ — Policy Enforcement Point (PEP): HTTPS server requiring mutual TLS, extracts verified device identity from the certificate itself (never a client-supplied header)
- policy_engine/ — Policy Decision Point (PDP): evaluates identity + context against policies/policy.json
- devices/ — simulated IoT devices (sensor, actuator, admin) presenting their issued certificates
- logs/audit.log — full decision trail for every request

## How to run
See run_demo.ps1 in the project root.
