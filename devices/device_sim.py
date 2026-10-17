import ssl, sys, os, http.client

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def call(device_id, resource, host="127.0.0.1", port=8443):
    cert_dir = os.path.join(BASE, "certs", "devices")
    certfile = os.path.join(cert_dir, f"{device_id}.crt")
    keyfile = os.path.join(cert_dir, f"{device_id}.key")
    cafile = os.path.join(BASE, "ca", "ca_cert.pem")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)
    context.check_hostname = False
    if os.path.exists(certfile):
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    else:
        print(f"[{device_id}] NO CERTIFICATE PRESENT -> expecting hard TLS rejection")

    conn = http.client.HTTPSConnection(host, port, context=context, timeout=5)
    try:
        conn.request("GET", resource)
        resp = conn.getresponse()
        body = resp.read().decode()
        print(f"[{device_id}] GET {resource} -> HTTP {resp.status} :: {body}")
    except Exception as e:
        print(f"[{device_id}] GET {resource} -> CONNECTION REJECTED AT TLS LAYER :: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    device_id = sys.argv[1]
    resource = sys.argv[2] if len(sys.argv) > 2 else "/telemetry"
    call(device_id, resource)
