import datetime, os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT = os.path.dirname(os.path.abspath(__file__))
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "MU"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust IoT Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "ZeroTrust-IoT Root CA"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)
with open(os.path.join(OUT, "ca_key.pem"), "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open(os.path.join(OUT, "ca_cert.pem"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("Root CA generated: ca_cert.pem, ca_key.pem")
