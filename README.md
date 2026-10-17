# Zero Trust for IoT Devices

A software-only Zero Trust security architecture for IoT-style devices, built and proven
against all four NIST SP 800-207 tenets, then stress-tested with real attack tooling
against a self-hosted fake-company Active Directory domain.

## Architecture
![architecture](docs/architecture.png)

## What it proves
| Tenet | Proof |
|---|---|
| Verify Explicitly | mTLS handshake rejection for devices with no certificate |
| Least Privilege | Resource-level deny for mismatched device type |
| Assume Breach | Instant deny on a revoked device certificate |
| Continuous Verification | Adaptive risk engine degrades trust on burst traffic in a 10s sliding window |

## Advanced features
- **Self-healing auto-containment** — 3 consecutive anomaly strikes auto-revokes a device's
  certificate with no human in the loop (`policy_engine/risk_engine.py`).
- **Tamper-evident audit log** — every decision is SHA-256 hash-chained
  (`gateway/audit_chain.py`, verified by `verify_audit_chain.py`).

## Attack simulation
A Samba4 AD DC (`ACMEFAKECORP.LOCAL`, 5 departments, 13 users) was provisioned inside an
isolated Kali Linux VM and attacked with `nmap`, `smbclient` and `netexec` (see
`docs/attack_chain.png`). No real hardware, no cloud subscription, no Docker — everything
is reproducible from PowerShell.

## Running it
```powershell
.\venv\Scripts\python.exe gateway\app.py
.\venv\Scripts\python.exe devices\device_sim.py sensor-01 /telemetry
.\venv\Scripts\python.exe verify_audit_chain.py
```

## Author
Shalleel Mohamud — BSc (Hons) Computer Science with Network Security, University of
Technology, Mauritius (UTM)
