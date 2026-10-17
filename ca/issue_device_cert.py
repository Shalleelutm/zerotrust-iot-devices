import sys, os, json, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_DIR = os.path.join(BASE, "ca")
DEV_CERT_DIR = os.path.join(BASE, "certs", "devices")
REGISTRY = os.path.join(BASE, "policies", "devices.json")

def load_ca():
    with open(os.path.join(CA_DIR, "ca_key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(CA_DIR, "ca_cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def issue(device_id, device_type, trust_score, valid_days=365):
    ca_key, ca_cert = load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, device_type),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=valid_days))
        .sign(ca_key, hashes.SHA256())
    )
    os.makedirs(DEV_CERT_DIR, exist_ok=True)
    with open(os.path.join(DEV_CERT_DIR, f"{device_id}.key"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(os.path.join(DEV_CERT_DIR, f"{device_id}.crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    registry = {}
    if os.path.exists(REGISTRY):
        with open(REGISTRY) as f:
            registry = json.load(f)
    registry[device_id] = {"device_type": device_type, "trust_score": trust_score, "revoked": False, "serial": str(cert.serial_number)}
    os.makedirs(os.path.dirname(REGISTRY), exist_ok=True)
    with open(REGISTRY, "w") as f:
        json.dump(registry, f, indent=2)
    print(f"Issued cert for {device_id} ({device_type}, trust={trust_score})")

if __name__ == "__main__":
    issue(sys.argv[1], sys.argv[2], float(sys.argv[3]))
