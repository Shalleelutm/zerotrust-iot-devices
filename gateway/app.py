import ssl, os, json, datetime, http.server, socketserver, sys, traceback

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE, "logs", "audit.log")
sys.path.insert(0, BASE)
from policy_engine.pdp import evaluate

def log_decision(device_id, resource, allowed, reason):
    entry = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "device_id": device_id,
             "resource": resource, "decision": "ALLOW" if allowed else "DENY", "reason": reason}
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[{entry['decision']}] {device_id} -> {resource} :: {reason}", flush=True)

class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        try:
            peer_cert = self.connection.getpeercert()
            device_id = "unverified"
            if peer_cert:
                for field in peer_cert.get("subject", []):
                    for key, value in field:
                        if key == "commonName":
                            device_id = value
            resource = self.path
            allowed, reason = evaluate(device_id, resource)
            log_decision(device_id, resource, allowed, reason)
            body = json.dumps({"status": "ALLOW" if allowed else "DENY", "reason": reason}).encode()
            self.send_response(200 if allowed else 403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            print("HANDLER ERROR:", traceback.format_exc(), flush=True)
            try:
                body = json.dumps({"status": "ERROR", "reason": str(e)}).encode()
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def log_message(self, format, *args): pass

class TLSServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, ssl_context):
        self.ssl_context = ssl_context
        super().__init__(server_address, handler_class)

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        try:
            connstream = self.ssl_context.wrap_socket(newsocket, server_side=True)
        except ssl.SSLError as e:
            print(f"[TLS HANDSHAKE FAILED] {fromaddr}: {e}", flush=True)
            newsocket.close()
            raise
        return connstream, fromaddr

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=os.path.join(BASE, "certs", "devices", "gateway.crt"),
        keyfile=os.path.join(BASE, "certs", "devices", "gateway.key"),
    )
    context.load_verify_locations(cafile=os.path.join(BASE, "ca", "ca_cert.pem"))
    context.verify_mode = ssl.CERT_REQUIRED

    server = TLSServer(("127.0.0.1", 8443), Handler, context)
    print("Zero Trust Gateway (Policy Enforcement Point) listening on https://127.0.0.1:8443", flush=True)
    print("Audit log:", LOG_FILE, flush=True)
    server.serve_forever()
