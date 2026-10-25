"""Tests for the SQLite-backed JWKS server."""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import jwt

import database
import main


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = database.connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_empty_db_has_no_keys(self):
        self.assertIsNone(database.get_key(self.conn))
        self.assertIsNone(database.get_key(self.conn, expired=True))
        self.assertEqual(database.get_valid_keys(self.conn), [])

    def test_insert_and_select_by_expiry(self):
        now = int(time.time())
        valid = database.insert_key(self.conn, b"valid", now + 100)
        expired = database.insert_key(self.conn, b"expired", now - 100)
        self.assertEqual(database.get_key(self.conn)[0], valid)
        self.assertEqual(database.get_key(self.conn, expired=True)[0], expired)
        self.assertEqual([r[0] for r in database.get_valid_keys(self.conn)], [valid])

    def test_injection_value_is_stored_literally(self):
        payload = b"x'); DROP TABLE keys; --"
        kid = database.insert_key(self.conn, payload, time.time() + 100)
        self.assertEqual(database.get_key(self.conn)[:2], (kid, payload))
        self.assertEqual(database.get_valid_keys(self.conn)[0][0], kid)

    def test_ensure_keys_seeds_once(self):
        main.ensure_keys(self.conn)
        main.ensure_keys(self.conn)
        count = self.conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        self.assertEqual(count, 2)

    def test_int_to_base64(self):
        self.assertEqual(main.int_to_base64(65537), "AQAB")
        self.assertEqual(main.int_to_base64(1), "AQ")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.db_file = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls.server = main.make_server("127.0.0.1", 0, cls.db_file)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        main.MyServer.db.close()
        os.remove(cls.db_file)

    def request(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            with err:
                return err.code, err.read()

    def jwks(self):
        status, body = self.request("GET", "/.well-known/jwks.json")
        self.assertEqual(status, 200)
        return json.loads(body)["keys"]

    def test_db_file_has_valid_and_expired_keys(self):
        conn = database.connect(self.db_file)
        try:
            self.assertIsNotNone(database.get_key(conn))
            self.assertIsNotNone(database.get_key(conn, expired=True))
        finally:
            conn.close()

    def test_valid_jwt_verifies_against_jwks(self):
        body = json.dumps({"username": "userABC", "password": "password123"}).encode()
        status, token = self.request("POST", "/auth", body,
                                     {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        kid = jwt.get_unverified_header(token)["kid"]
        jwk = next(k for k in self.jwks() if k["kid"] == kid)
        key = jwt.PyJWK.from_dict(jwk).key
        claims = jwt.decode(token, key, algorithms=["RS256"])
        self.assertEqual(claims["user"], "username")

    def test_expired_jwt_not_in_jwks(self):
        status, token = self.request("POST", "/auth?expired=true")
        self.assertEqual(status, 200)
        kid = jwt.get_unverified_header(token)["kid"]
        self.assertNotIn(kid, [k["kid"] for k in self.jwks()])
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertLess(claims["exp"], time.time())

    def test_bad_methods_and_paths(self):
        for method, path in [("PUT", "/auth"), ("PATCH", "/auth"), ("DELETE", "/auth"),
                             ("HEAD", "/auth"), ("GET", "/auth"),
                             ("POST", "/.well-known/jwks.json"), ("POST", "/nope")]:
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path)[0], 405)

    def test_auth_without_suitable_key(self):
        saved = main.MyServer.db
        main.MyServer.db = database.connect(":memory:")
        try:
            self.assertEqual(self.request("POST", "/auth")[0], 500)
        finally:
            main.MyServer.db.close()
            main.MyServer.db = saved


if __name__ == "__main__":
    unittest.main()
