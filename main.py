"""JWKS server backed by a SQLite key store.

Endpoints:
    POST /auth                   -> signed JWT (``?expired`` signs with an expired key)
    GET  /.well-known/jwks.json  -> public JWKs for all unexpired keys
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

import database

hostName = "localhost"
serverPort = 8080


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def generate_pem():
    """Generate a new RSA private key serialized as PKCS1 PEM bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def ensure_keys(conn, now=None):
    """Make sure the DB holds at least one valid and one expired key."""
    now = int(time.time()) if now is None else int(now)
    if database.get_key(conn, expired=False, now=now) is None:
        database.insert_key(conn, generate_pem(), now + 3600)
    if database.get_key(conn, expired=True, now=now) is None:
        database.insert_key(conn, generate_pem(), now - 3600)


class MyServer(BaseHTTPRequestHandler):
    # Set on the class before serving; shared sqlite3 connection.
    db = None

    def _send(self, status, body=None, content_type="application/json"):
        """Send a response with an optional body."""
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body is not None:
            self.wfile.write(body)

    def _method_not_allowed(self):
        self._send(405)

    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_HEAD = _method_not_allowed

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path != "/auth":
            self._method_not_allowed()
            return

        # Drain the request body (Basic auth / JSON creds are mocked, not checked).
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

        expired = 'expired' in parse_qs(parsed_path.query)
        row = database.get_key(self.db, expired=expired)
        if row is None:
            self._send(500, b'{"error": "no suitable key available"}')
            return

        kid, pem, exp = row
        token_payload = {"user": "username", "exp": exp}
        encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256",
                                 headers={"kid": str(kid)})
        self._send(200, encoded_jwt.encode("utf-8"), "text/plain")

    def do_GET(self):
        if urlparse(self.path).path != "/.well-known/jwks.json":
            self._method_not_allowed()
            return

        jwks = []
        for kid, pem, _exp in database.get_valid_keys(self.db):
            public = serialization.load_pem_private_key(pem, password=None) \
                .public_key().public_numbers()
            jwks.append({
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(public.n),
                "e": int_to_base64(public.e),
            })
        self._send(200, json.dumps({"keys": jwks}).encode("utf-8"))


def make_server(host=hostName, port=serverPort, db_file=database.DB_FILE):
    """Open the key store, seed keys, and build the HTTP server."""
    MyServer.db = database.connect(db_file)
    ensure_keys(MyServer.db)
    return HTTPServer((host, port), MyServer)


if __name__ == "__main__":  # pragma: no cover
    webServer = make_server()
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    MyServer.db.close()
