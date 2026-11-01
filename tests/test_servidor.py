import http.client
import ipaddress
import json
import re
import tempfile
import threading
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile
from xml.etree import ElementTree

import servidor


class GameServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scheme_override = patch.object(servidor, "PUBLIC_SCHEME", "http")
        cls.scheme_override.start()
        cls.proxy_override = patch.object(servidor, "TRUSTED_PROXY_NETWORKS", ())
        cls.proxy_override.start()
        cls.server = servidor.ThreadingHTTPServer(("127.0.0.1", 0), servidor.GameHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.host, cls.port = cls.server.server_address
        cls.origin = f"http://{cls.host}:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()
        cls.scheme_override.stop()
        cls.proxy_override.stop()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_override = patch.object(
            servidor, "DATABASE", Path(self.temp_dir.name) / "test.db"
        )
        self.database_override.start()
        servidor.initialize_database()
        servidor.RATE_LIMITER = servidor.RateLimiter()

    def tearDown(self):
        self.database_override.stop()
        self.temp_dir.cleanup()

    def request(self, path, method="GET", payload=None, headers=None):
        request_headers = dict(headers or {})
        body = None
        if payload is not None:
            body = json.dumps(payload)
            request_headers.setdefault("Content-Type", "application/json")
        if method != "GET":
            request_headers.setdefault("Origin", self.origin)
        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        result_headers = response.headers
        connection.close()
        return response.status, result_headers, response_body

    def create_account(self):
        with patch("servidor.send_email_code") as send_code:
            status, _, body = self.request(
                "/api/auth/code",
                "POST",
                {
                    "purpose": "register",
                    "username": "pilot",
                    "email": "pilot@example.com",
                },
            )
            self.assertEqual(status, 202)
            challenge_id = json.loads(body)["challengeId"]
            code = send_code.call_args.args[1]
            status, headers, body = self.request(
                "/api/auth/verify",
                "POST",
                {"challengeId": challenge_id, "code": code},
            )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["user"]["username"], "pilot")
        session_cookie = headers.get("Set-Cookie")
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Strict", session_cookie)
        with servidor.database() as connection:
            user = connection.execute(
                "SELECT email FROM users WHERE username = 'pilot'"
            ).fetchone()
        self.assertEqual(user["email"], "pilot@example.com")
        return session_cookie.split(";", 1)[0]

    def start_game_run(self, session_cookie):
        status, _, body = self.request(
            "/api/games/start",
            "POST",
            {},
            {"Cookie": session_cookie},
        )
        self.assertEqual(status, 201)
        run_id = json.loads(body)["runId"]
        self.assertRegex(run_id, r"^[A-Za-z0-9_-]{43}$")
        return run_id

    def request_code(self, purpose, email, username=None, password=None):
        payload = {"purpose": purpose, "email": email}
        if username is not None:
            payload["username"] = username
        if password is not None:
            payload["password"] = password
        with patch("servidor.send_email_code") as send_code:
            status, _, body = self.request("/api/auth/code", "POST", payload)
        return status, json.loads(body), send_code

    def test_index_uses_nonce_csp_and_security_headers(self):
        status, headers, body = self.request("/")
        html = body.decode("utf-8")
        nonce = re.search(r"<script nonce=\"([^\"]+)\"", html).group(1)
        style_nonce = re.search(r"<style nonce=\"([^\"]+)\"", html).group(1)

        self.assertEqual(status, 200)
        self.assertNotRegex(html, r"\sstyle\s*=")
        self.assertIn(f"'nonce-{nonce}'", headers["Content-Security-Policy"])
        self.assertIn(f"'nonce-{style_nonce}'", headers["Content-Security-Policy"])
        self.assertNotIn("'unsafe-inline'", headers["Content-Security-Policy"])
        self.assertIn("worker-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Permitted-Cross-Domain-Policies"], "none")

    def test_mobile_app_assets_are_not_served(self):
        for path in (
            "/manifest.webmanifest",
            "/service-worker.js",
            "/icons/orbita-180.png",
            "/icons/orbita-192.png",
            "/icons/orbita-512.png",
        ):
            with self.subTest(path=path):
                status, _, _ = self.request(path)
                self.assertEqual(status, 404)

    def test_rejects_cross_origin_state_changes(self):
        status, _, _ = self.request(
            "/api/auth/code",
            "POST",
            {"purpose": "register", "username": "pilot", "email": "pilot@example.com"},
            {"Origin": "https://attacker.example"},
        )
        self.assertEqual(status, 403)

    def test_requires_the_configured_public_scheme(self):
        with patch.object(servidor, "PUBLIC_SCHEME", "https"):
            status, _, _ = self.request(
                "/api/auth/code",
                "POST",
                {"purpose": "register", "username": "pilot", "email": "pilot@example.com"},
            )
        self.assertEqual(status, 403)

    def test_https_sessions_receive_secure_cookie(self):
        with patch.object(servidor, "PUBLIC_SCHEME", "https"), patch(
            "servidor.send_email_code"
        ) as send_code:
            status, _, body = self.request(
                "/api/auth/code",
                "POST",
                {"purpose": "register", "username": "pilot", "email": "pilot@example.com"},
                {"Origin": f"https://{self.host}:{self.port}"},
            )
            self.assertEqual(status, 202)
            challenge_id = json.loads(body)["challengeId"]
            status, headers, _ = self.request(
                "/api/auth/verify",
                "POST",
                {"challengeId": challenge_id, "code": send_code.call_args.args[1]},
                {"Origin": f"https://{self.host}:{self.port}"},
            )
        self.assertEqual(status, 200)
        self.assertIn("__Host-orbita_session=", headers.get("Set-Cookie"))
        self.assertIn("Secure", headers.get("Set-Cookie"))
        self.assertEqual(headers.get("Strict-Transport-Security"), "max-age=31536000")

    def test_requires_json_content_type(self):
        status, _, _ = self.request(
            "/api/auth/code",
            "POST",
            {"purpose": "register", "username": "pilot", "email": "pilot@example.com"},
            {"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 415)

    def test_rejects_transfer_encoded_json_requests(self):
        status, _, _ = self.request(
            "/api/auth/code",
            "POST",
            {"purpose": "register", "username": "pilot", "email": "pilot@example.com"},
            {"Transfer-Encoding": "chunked"},
        )
        self.assertEqual(status, 400)

    def test_rejects_duplicate_content_length_headers(self):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        connection.putrequest("POST", "/api/auth/code")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Origin", self.origin)
        connection.putheader("Content-Length", "2")
        connection.putheader("Content-Length", "2")
        connection.endheaders(b"{}")
        response = connection.getresponse()
        response.read()
        connection.close()
        self.assertEqual(response.status, 400)

    def test_rate_limits_game_run_creation(self):
        session_cookie = self.create_account()
        headers = {"Cookie": session_cookie}
        with patch.dict(servidor.RATE_LIMITS, {"/api/games/start": (1, 60)}):
            status, _, _ = self.request("/api/games/start", "POST", {}, headers)
            self.assertEqual(status, 201)
            status, _, _ = self.request("/api/games/start", "POST", {}, headers)
        self.assertEqual(status, 429)

    def test_rate_limits_public_leaderboard_reads(self):
        with patch.dict(servidor.RATE_LIMITS, {"/api/leaderboard": (1, 60)}):
            status, _, _ = self.request("/api/leaderboard")
            self.assertEqual(status, 200)
            status, _, _ = self.request("/api/leaderboard")
        self.assertEqual(status, 429)

    def test_rejects_scores_inconsistent_with_duration(self):
        session_cookie = self.create_account()
        headers = {"Cookie": session_cookie}
        run_id = self.start_game_run(session_cookie)

        status, _, _ = self.request(
            "/api/games",
            "POST",
            {"runId": run_id, "score": 900, "durationSeconds": 10},
            headers,
        )
        self.assertEqual(status, 400)

        with servidor.database() as connection:
            connection.execute(
                "UPDATE game_runs SET started_at = started_at - 11 WHERE run_hash = ?",
                (servidor.token_digest(run_id),),
            )
        status, _, _ = self.request(
            "/api/games",
            "POST",
            {"runId": run_id, "score": 109, "durationSeconds": 10},
            headers,
        )
        self.assertEqual(status, 201)

        status, _, _ = self.request(
            "/api/games",
            "POST",
            {"runId": run_id, "score": 109, "durationSeconds": 10},
            headers,
        )
        self.assertEqual(status, 400)

    def test_rejects_game_submission_without_server_run(self):
        session_cookie = self.create_account()
        status, _, _ = self.request(
            "/api/games",
            "POST",
            {"score": 109, "durationSeconds": 10},
            {"Cookie": session_cookie},
        )
        self.assertEqual(status, 400)

    def test_rejects_score_faster_than_server_elapsed_time(self):
        session_cookie = self.create_account()
        headers = {"Cookie": session_cookie}
        run_id = self.start_game_run(session_cookie)

        status, _, _ = self.request(
            "/api/games",
            "POST",
            {"runId": run_id, "score": 109, "durationSeconds": 10},
            headers,
        )

        self.assertEqual(status, 400)
        with servidor.database() as connection:
            games = connection.execute("SELECT COUNT(*) FROM games").fetchone()[0]
        self.assertEqual(games, 0)

    def test_authenticates_with_http_only_cookie_not_bearer_header(self):
        session_cookie = self.create_account()
        status, _, _ = self.request(
            "/api/me",
            headers={"Authorization": f"Bearer {session_cookie.split('=', 1)[1]}"},
        )
        self.assertEqual(status, 401)

        status, _, _ = self.request(
            "/api/me",
            headers={"Cookie": "orbita_session=é"},
        )
        self.assertEqual(status, 401)

        status, _, body = self.request("/api/me", headers={"Cookie": session_cookie})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["user"]["username"], "pilot")

    def test_logout_revokes_and_clears_session_cookie(self):
        session_cookie = self.create_account()
        status, headers, _ = self.request(
            "/api/logout",
            "POST",
            {},
            {"Cookie": session_cookie},
        )
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers.get("Set-Cookie"))
        status, _, _ = self.request("/api/me", headers={"Cookie": session_cookie})
        self.assertEqual(status, 401)

    def test_rate_limiter_rejects_excess_requests(self):
        limiter = servidor.RateLimiter()
        limiter.check(("login", "127.0.0.1"), 1, 60)
        with self.assertRaises(servidor.RequestError) as error:
            limiter.check(("login", "127.0.0.1"), 1, 60)
        self.assertEqual(error.exception.status, 429)
        self.assertGreater(error.exception.retry_after, 0)

    def test_rate_limiter_uses_forwarded_ip_only_for_trusted_proxies(self):
        with patch.object(
            servidor,
            "TRUSTED_PROXY_NETWORKS",
            (ipaddress.ip_network("127.0.0.1/32"),),
        ), patch("servidor.send_email_code"):
            status, _, _ = self.request(
                "/api/auth/code",
                "POST",
                {"purpose": "register", "username": "pilot", "email": "pilot@example.com"},
                {"X-Forwarded-For": "203.0.113.7"},
            )
        self.assertEqual(status, 202)
        self.assertIn(("/api/auth/code", "203.0.113.7"), servidor.RATE_LIMITER.entries)

    def test_email_code_registration_and_passwordless_login(self):
        self.create_account()
        status, response, send_code = self.request_code("login", "PILOT@example.com")
        self.assertEqual(status, 202)
        send_code.assert_called_once()
        self.assertEqual(send_code.call_args.args[0], "pilot@example.com")
        challenge_id = response["challengeId"]
        status, headers, body = self.request(
            "/api/auth/verify",
            "POST",
            {"challengeId": challenge_id, "code": send_code.call_args.args[1]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["user"]["username"], "pilot")
        self.assertIn("HttpOnly", headers.get("Set-Cookie"))
        status, _, _ = self.request(
            "/api/auth/verify",
            "POST",
            {"challengeId": challenge_id, "code": send_code.call_args.args[1]},
        )
        self.assertEqual(status, 400)

    def test_unknown_email_uses_generic_response_and_cannot_verify(self):
        status, response, send_code = self.request_code("login", "unknown@example.com")
        self.assertEqual(status, 202)
        self.assertFalse(send_code.called)
        self.assertNotIn("unknown@example.com", json.dumps(response))
        status, _, _ = self.request(
            "/api/auth/verify",
            "POST",
            {"challengeId": response["challengeId"], "code": "12345678"},
        )
        self.assertEqual(status, 400)

    def test_email_code_is_limited_to_five_attempts(self):
        status, response, send_code = self.request_code(
            "register", "pilot@example.com", username="pilot"
        )
        self.assertEqual(status, 202)
        challenge_id = response["challengeId"]
        for _ in range(servidor.EMAIL_CODE_ATTEMPTS):
            status, _, _ = self.request(
                "/api/auth/verify",
                "POST",
                {"challengeId": challenge_id, "code": "00000000"},
            )
            self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/api/auth/verify",
            "POST",
            {"challengeId": challenge_id, "code": send_code.call_args.args[1]},
        )
        self.assertEqual(status, 400)
        with servidor.database() as connection:
            user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(user_count, 0)

    def test_email_code_expires(self):
        status, response, send_code = self.request_code(
            "register", "pilot@example.com", username="pilot"
        )
        self.assertEqual(status, 202)
        with servidor.database() as connection:
            connection.execute(
                "UPDATE email_code_challenges SET expires_at = 0 WHERE challenge_id = ?",
                (response["challengeId"],),
            )
        status, _, _ = self.request(
            "/api/auth/verify",
            "POST",
            {"challengeId": response["challengeId"], "code": send_code.call_args.args[1]},
        )
        self.assertEqual(status, 400)

    def test_email_delivery_failure_does_not_leave_usable_code(self):
        with patch("servidor.send_email_code", side_effect=RuntimeError("SMTP unavailable")):
            status, _, _ = self.request(
                "/api/auth/code",
                "POST",
                {"purpose": "register", "email": "pilot@example.com", "username": "pilot"},
            )
        self.assertEqual(status, 503)
        with servidor.database() as connection:
            challenge_count = connection.execute(
                "SELECT COUNT(*) FROM email_code_challenges"
            ).fetchone()[0]
        self.assertEqual(challenge_count, 0)

    def test_legacy_account_can_link_verified_email_and_keeps_history(self):
        salt = b"legacy-user-salt!"
        with servidor.database() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, password_salt, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    "legacy",
                    servidor.password_digest("old-password-123", salt),
                    salt,
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            user_id = cursor.lastrowid
            connection.execute(
                """
                INSERT INTO games (user_id, score, duration_seconds, played_at)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, 109, 10, "2026-01-02T00:00:00+00:00"),
            )
        status, response, send_code = self.request_code(
            "link",
            "legacy@example.com",
            username="legacy",
            password="old-password-123",
        )
        self.assertEqual(status, 202)
        self.assertTrue(send_code.called)
        status, headers, body = self.request(
            "/api/auth/verify",
            "POST",
            {"challengeId": response["challengeId"], "code": send_code.call_args.args[1]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["user"]["username"], "legacy")
        self.assertIn("HttpOnly", headers.get("Set-Cookie"))
        with servidor.database() as connection:
            user = connection.execute(
                "SELECT email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            game_count = connection.execute(
                "SELECT COUNT(*) FROM games WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
        self.assertEqual(user["email"], "legacy@example.com")
        self.assertEqual(game_count, 1)

    def test_database_migrates_existing_users_without_losing_them(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        with patch.object(servidor, "DATABASE", legacy_path):
            with servidor.database() as connection:
                connection.execute(
                    """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                        password_hash BLOB NOT NULL,
                        password_salt BLOB NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO users (username, password_hash, password_salt, created_at)
                    VALUES ('legacy', X'01', X'02', '2026-01-01T00:00:00+00:00')
                    """
                )
            servidor.initialize_database()
            with servidor.database() as connection:
                user = connection.execute(
                    "SELECT username, email FROM users WHERE username = 'legacy'"
                ).fetchone()
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(users)")
                }
            self.assertIn("email", columns)
            self.assertEqual(user["username"], "legacy")
            self.assertIsNone(user["email"])

    def test_excel_export_contains_only_authenticated_users_sorted_scores(self):
        session_cookie = self.create_account()
        with servidor.database() as connection:
            pilot_id = connection.execute(
                "SELECT id FROM users WHERE username = 'pilot'"
            ).fetchone()["id"]
            other_salt = b"other-user-salt!"
            other_cursor = connection.execute(
                """
                INSERT INTO users (username, email, password_hash, password_salt, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "other",
                    "private@example.com",
                    servidor.password_digest("unused-password", other_salt),
                    other_salt,
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            connection.executemany(
                """
                INSERT INTO games (user_id, score, duration_seconds, played_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (pilot_id, 109, 10, "2026-02-01T00:00:00+00:00"),
                    (pilot_id, 209, 20, "2026-02-02T00:00:00+00:00"),
                    (other_cursor.lastrowid, 999, 99, "2026-02-03T00:00:00+00:00"),
                ],
            )
        status, headers, body = self.request(
            "/api/me/export.xlsx", headers={"Cookie": session_cookie}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("Content-Type"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertEqual(
            headers.get("Content-Disposition"),
            'attachment; filename="orbita-mis-partidas.xlsx"',
        )
        with ZipFile(BytesIO(body)) as workbook:
            self.assertIsNone(workbook.testzip())
            self.assertEqual(
                set(workbook.namelist()),
                {
                    "[Content_Types].xml",
                    "_rels/.rels",
                    "xl/workbook.xml",
                    "xl/_rels/workbook.xml.rels",
                    "xl/worksheets/sheet1.xml",
                    "xl/styles.xml",
                },
            )
            sheet = ElementTree.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
            relationships = ElementTree.fromstring(
                workbook.read("xl/_rels/workbook.xml.rels")
            )
            content_types = ElementTree.fromstring(workbook.read("[Content_Types].xml"))
            for name in workbook.namelist():
                if name.endswith(".xml"):
                    ElementTree.fromstring(workbook.read(name))
        self.assertTrue(
            any(
                relationship.get("Type", "").endswith("/styles")
                and relationship.get("Target") == "styles.xml"
                for relationship in relationships
            )
        )
        self.assertTrue(
            any(
                item.get("PartName") == "/xl/styles.xml"
                and item.get("ContentType")
                == "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"
                for item in content_types
            )
        )
        sheet_text = "".join(sheet.itertext())
        self.assertIn("pilot", sheet_text)
        self.assertNotIn("other", sheet_text)
        self.assertNotIn("private@example.com", sheet_text)
        scores = [
            int(cell.find("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}v").text)
            for cell in sheet.findall(
                ".//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c"
            )
            if cell.get("r") in ("B2", "B3")
        ]
        self.assertEqual(scores, [209, 109])

    def test_excel_export_requires_session(self):
        status, _, _ = self.request("/api/me/export.xlsx")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
