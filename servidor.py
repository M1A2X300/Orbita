import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import smtplib
import ssl
import sqlite3
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from io import BytesIO
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("ORBITA_DATABASE", ROOT / "orbita.db"))
HOST = os.environ.get("ORBITA_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
PUBLIC_SCHEME = os.environ.get("ORBITA_PUBLIC_SCHEME", "http").lower()
if PUBLIC_SCHEME not in ("http", "https"):
    raise RuntimeError("ORBITA_PUBLIC_SCHEME debe ser http o https.")
TRUSTED_PROXY_NETWORKS = tuple(
    ipaddress.ip_network(value.strip(), strict=False)
    for value in os.environ.get("ORBITA_TRUSTED_PROXIES", "").split(",")
    if value.strip()
)
SESSION_SECONDS = 30 * 24 * 60 * 60
PASSWORD_ITERATIONS = 310_000
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MAX_BODY_BYTES = 16_384
RATE_LIMITS = {
    "/api/auth/code": (10, 15 * 60),
    "/api/auth/verify": (20, 15 * 60),
    "/api/games/start": (30, 60),
    "/api/games": (30, 60),
    "/api/logout": (10, 60),
    "/api/shutdown": (3, 60),
    "/api/me": (120, 60),
    "/api/leaderboard": (60, 60),
    "/api/me/export.xlsx": (5, 60 * 60),
}
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
EMAIL_CODE_SECONDS = 10 * 60
EMAIL_CODE_ATTEMPTS = 5
EMAIL_CODE_MAX_PER_ADDRESS = 5
configured_email_code_pepper = os.environ.get("ORBITA_EMAIL_CODE_PEPPER", "").encode("utf-8")
if len(configured_email_code_pepper) < 32 and PUBLIC_SCHEME == "https":
    raise RuntimeError(
        "Configura ORBITA_EMAIL_CODE_PEPPER con al menos 32 caracteres para HTTPS."
    )
EMAIL_CODE_PEPPER = configured_email_code_pepper
if len(EMAIL_CODE_PEPPER) < 32:
    EMAIL_CODE_PEPPER = secrets.token_bytes(32)
LEGACY_LINK_DUMMY_SALT = secrets.token_bytes(16)
LEGACY_LINK_DUMMY_HASH = hashlib.pbkdf2_hmac(
    "sha256", b"not-a-real-password", LEGACY_LINK_DUMMY_SALT, PASSWORD_ITERATIONS
)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-src 'none'; frame-ancestors 'none'; "
        "worker-src 'none'; manifest-src 'none'; media-src 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-Frame-Options": "DENY",
}
STATIC_FILES = {
    "/icons/orbita.svg": ("icons/orbita.svg", "image/svg+xml", "public, max-age=86400"),
    "/icons/orbita.ico": ("icons/orbita.ico", "image/vnd.microsoft.icon", "public, max-age=86400"),
}


def connect_database():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database():
    connection = connect_database()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS games (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                score INTEGER NOT NULL CHECK (score >= 0),
                duration_seconds INTEGER NOT NULL CHECK (duration_seconds >= 0),
                played_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS game_runs (
                run_hash BLOB PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                started_at REAL NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS games_ranking ON games(score DESC, user_id);
            CREATE INDEX IF NOT EXISTS games_user_history ON games(user_id, played_at DESC);
            CREATE INDEX IF NOT EXISTS game_runs_expiry ON game_runs(expires_at);
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(users)")
        }
        if "email" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN email TEXT")
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
            ON users(email COLLATE NOCASE)
            WHERE email IS NOT NULL
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS email_code_challenges (
                challenge_id TEXT PRIMARY KEY,
                purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login', 'link')),
                email TEXT NOT NULL COLLATE NOCASE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                username TEXT,
                code_hash BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS email_code_challenges_email
            ON email_code_challenges(email, purpose, created_at DESC)
            """
        )


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


def normalize_email(value):
    if not isinstance(value, str):
        raise RequestError(400, "Escribe un correo electrónico válido.")
    email = value.strip()
    if (
        not 3 <= len(email) <= 254
        or not email.isascii()
        or not EMAIL_PATTERN.fullmatch(email)
    ):
        raise RequestError(400, "Escribe un correo electrónico válido.")
    local, _domain = email.rsplit("@", 1)
    if local.startswith(".") or local.endswith(".") or ".." in local or len(local) > 64:
        raise RequestError(400, "Escribe un correo electrónico válido.")
    return email.casefold()


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).digest()


def email_code_digest(challenge_id, code):
    message = f"{challenge_id}:{code}".encode("ascii")
    return hmac.new(EMAIL_CODE_PEPPER, message, hashlib.sha256).digest()


def send_email_code(recipient, code):
    host = os.environ.get("ORBITA_SMTP_HOST", "").strip()
    username = os.environ.get("ORBITA_SMTP_USERNAME", "")
    password = os.environ.get("ORBITA_SMTP_PASSWORD", "")
    sender = os.environ.get("ORBITA_SMTP_FROM", username).strip()
    security = os.environ.get("ORBITA_SMTP_SECURITY", "starttls").strip().lower()
    if not host or not sender or bool(username) != bool(password):
        raise RuntimeError("Configura ORBITA_SMTP_HOST, ORBITA_SMTP_FROM y las credenciales SMTP.")
    if any(character in host + sender + username for character in "\r\n"):
        raise RuntimeError("La configuración SMTP contiene un valor no válido.")
    if security not in ("starttls", "ssl"):
        raise RuntimeError("ORBITA_SMTP_SECURITY debe ser starttls o ssl.")
    default_port = "465" if security == "ssl" else "587"
    try:
        port = int(os.environ.get("ORBITA_SMTP_PORT", default_port))
    except ValueError as error:
        raise RuntimeError("ORBITA_SMTP_PORT debe ser un puerto válido.") from error
    if not 1 <= port <= 65535:
        raise RuntimeError("ORBITA_SMTP_PORT debe ser un puerto válido.")

    message = EmailMessage()
    message["Subject"] = "Tu código de acceso a Órbita"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Tu código para Órbita es {code}.\n\n"
        "Vence en 10 minutos y solo se puede usar una vez. "
        "Si no solicitaste este código, ignora este correo."
    )
    context = ssl.create_default_context()
    if security == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=10, context=context) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message)


def build_personal_workbook(username, games):
    spreadsheet_ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    office_rel_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    package_rel_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    content_types_ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    ElementTree.register_namespace("", spreadsheet_ns)
    ElementTree.register_namespace("r", office_rel_ns)

    sheet = ElementTree.Element(f"{{{spreadsheet_ns}}}worksheet")
    views = ElementTree.SubElement(sheet, f"{{{spreadsheet_ns}}}sheetViews")
    view = ElementTree.SubElement(
        views, f"{{{spreadsheet_ns}}}sheetView", {"workbookViewId": "0"}
    )
    ElementTree.SubElement(
        view,
        f"{{{spreadsheet_ns}}}pane",
        {"ySplit": "1", "topLeftCell": "A2", "activePane": "bottomLeft", "state": "frozen"},
    )
    ElementTree.SubElement(
        sheet,
        f"{{{spreadsheet_ns}}}cols",
    )
    columns = sheet.find(f"{{{spreadsheet_ns}}}cols")
    for index, width in enumerate((22, 14, 22, 28), start=1):
        ElementTree.SubElement(
            columns,
            f"{{{spreadsheet_ns}}}col",
            {"min": str(index), "max": str(index), "width": str(width), "customWidth": "1"},
        )
    data = ElementTree.SubElement(sheet, f"{{{spreadsheet_ns}}}sheetData")

    def append_row(row_number, values, header=False):
        row = ElementTree.SubElement(
            data, f"{{{spreadsheet_ns}}}row", {"r": str(row_number)}
        )
        for column_number, value in enumerate(values):
            column_name = chr(ord("A") + column_number)
            cell = ElementTree.SubElement(
                row,
                f"{{{spreadsheet_ns}}}c",
                {"r": f"{column_name}{row_number}", **({"s": "1"} if header else {})},
            )
            if isinstance(value, int):
                ElementTree.SubElement(cell, f"{{{spreadsheet_ns}}}v").text = str(value)
            else:
                cell.set("t", "inlineStr")
                inline_string = ElementTree.SubElement(
                    cell, f"{{{spreadsheet_ns}}}is"
                )
                ElementTree.SubElement(
                    inline_string, f"{{{spreadsheet_ns}}}t"
                ).text = str(value)

    append_row(1, ("Jugador", "Puntos", "Duración (segundos)", "Fecha (UTC)"), header=True)
    for row_number, game in enumerate(games, start=2):
        append_row(
            row_number,
            (username, game["score"], game["duration_seconds"], game["played_at"]),
        )
    if games:
        ElementTree.SubElement(
            sheet,
            f"{{{spreadsheet_ns}}}autoFilter",
            {"ref": f"A1:D{len(games) + 1}"},
        )

    workbook = ElementTree.Element(f"{{{spreadsheet_ns}}}workbook")
    sheets = ElementTree.SubElement(workbook, f"{{{spreadsheet_ns}}}sheets")
    ElementTree.SubElement(
        sheets,
        f"{{{spreadsheet_ns}}}sheet",
        {"name": "Mis partidas", "sheetId": "1", f"{{{office_rel_ns}}}id": "rId1"},
    )

    relationships = ElementTree.Element(
        f"{{{package_rel_ns}}}Relationships"
    )
    ElementTree.SubElement(
        relationships,
        f"{{{package_rel_ns}}}Relationship",
        {
            "Id": "rId1",
            "Type": f"{office_rel_ns}/worksheet",
            "Target": "worksheets/sheet1.xml",
        },
    )
    ElementTree.SubElement(
        relationships,
        f"{{{package_rel_ns}}}Relationship",
        {
            "Id": "rId2",
            "Type": f"{office_rel_ns}/styles",
            "Target": "styles.xml",
        },
    )

    root_relationships = ElementTree.Element(
        f"{{{package_rel_ns}}}Relationships"
    )
    ElementTree.SubElement(
        root_relationships,
        f"{{{package_rel_ns}}}Relationship",
        {
            "Id": "rId1",
            "Type": f"{office_rel_ns}/officeDocument",
            "Target": "xl/workbook.xml",
        },
    )

    content_types = ElementTree.Element(f"{{{content_types_ns}}}Types")
    ElementTree.SubElement(
        content_types,
        f"{{{content_types_ns}}}Default",
        {"Extension": "rels", "ContentType": "application/vnd.openxmlformats-package.relationships+xml"},
    )
    ElementTree.SubElement(
        content_types,
        f"{{{content_types_ns}}}Default",
        {"Extension": "xml", "ContentType": "application/xml"},
    )
    ElementTree.SubElement(
        content_types,
        f"{{{content_types_ns}}}Override",
        {
            "PartName": "/xl/workbook.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        },
    )
    ElementTree.SubElement(
        content_types,
        f"{{{content_types_ns}}}Override",
        {
            "PartName": "/xl/worksheets/sheet1.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        },
    )
    ElementTree.SubElement(
        content_types,
        f"{{{content_types_ns}}}Override",
        {
            "PartName": "/xl/styles.xml",
            "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
        },
    )

    styles = ElementTree.Element(f"{{{spreadsheet_ns}}}styleSheet")
    fonts = ElementTree.SubElement(styles, f"{{{spreadsheet_ns}}}fonts", {"count": "2"})
    ElementTree.SubElement(fonts, f"{{{spreadsheet_ns}}}font")
    bold_font = ElementTree.SubElement(fonts, f"{{{spreadsheet_ns}}}font")
    ElementTree.SubElement(bold_font, f"{{{spreadsheet_ns}}}b")
    fills = ElementTree.SubElement(styles, f"{{{spreadsheet_ns}}}fills", {"count": "2"})
    ElementTree.SubElement(
        ElementTree.SubElement(fills, f"{{{spreadsheet_ns}}}fill"),
        f"{{{spreadsheet_ns}}}patternFill",
        {"patternType": "none"},
    )
    ElementTree.SubElement(
        ElementTree.SubElement(fills, f"{{{spreadsheet_ns}}}fill"),
        f"{{{spreadsheet_ns}}}patternFill",
        {"patternType": "gray125"},
    )
    borders = ElementTree.SubElement(styles, f"{{{spreadsheet_ns}}}borders", {"count": "1"})
    border = ElementTree.SubElement(borders, f"{{{spreadsheet_ns}}}border")
    for edge in ("left", "right", "top", "bottom", "diagonal"):
        ElementTree.SubElement(border, f"{{{spreadsheet_ns}}}{edge}")
    cell_style_xfs = ElementTree.SubElement(
        styles, f"{{{spreadsheet_ns}}}cellStyleXfs", {"count": "1"}
    )
    ElementTree.SubElement(cell_style_xfs, f"{{{spreadsheet_ns}}}xf", {"numFmtId": "0", "fontId": "0", "fillId": "0", "borderId": "0"})
    cell_xfs = ElementTree.SubElement(styles, f"{{{spreadsheet_ns}}}cellXfs", {"count": "2"})
    ElementTree.SubElement(cell_xfs, f"{{{spreadsheet_ns}}}xf", {"numFmtId": "0", "fontId": "0", "fillId": "0", "borderId": "0", "xfId": "0"})
    ElementTree.SubElement(cell_xfs, f"{{{spreadsheet_ns}}}xf", {"numFmtId": "0", "fontId": "1", "fillId": "0", "borderId": "0", "xfId": "0", "applyFont": "1"})
    cell_styles = ElementTree.SubElement(
        styles, f"{{{spreadsheet_ns}}}cellStyles", {"count": "1"}
    )
    ElementTree.SubElement(
        cell_styles,
        f"{{{spreadsheet_ns}}}cellStyle",
        {"name": "Normal", "xfId": "0", "builtinId": "0"},
    )

    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            ElementTree.tostring(content_types, encoding="utf-8", xml_declaration=True),
        )
        archive.writestr(
            "_rels/.rels",
            ElementTree.tostring(root_relationships, encoding="utf-8", xml_declaration=True),
        )
        archive.writestr(
            "xl/workbook.xml",
            ElementTree.tostring(workbook, encoding="utf-8", xml_declaration=True),
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            ElementTree.tostring(relationships, encoding="utf-8", xml_declaration=True),
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            ElementTree.tostring(sheet, encoding="utf-8", xml_declaration=True),
        )
        archive.writestr(
            "xl/styles.xml",
            ElementTree.tostring(styles, encoding="utf-8", xml_declaration=True),
        )
    return output.getvalue()


class RequestError(Exception):
    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


class RateLimiter:
    def __init__(self, max_entries=10_000):
        self.max_entries = max_entries
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def check(self, key, limit, period):
        now = time.monotonic()
        refill_rate = limit / period
        with self.lock:
            tokens, updated_at = self.entries.pop(key, (float(limit), now))
            tokens = min(float(limit), tokens + (now - updated_at) * refill_rate)
            if tokens < 1:
                self.entries[key] = (tokens, now)
                retry_after = max(1, math.ceil((1 - tokens) / refill_rate))
                raise RequestError(
                    429,
                    "Demasiados intentos. Espera un momento antes de volver a intentarlo.",
                    retry_after,
                )
            self.entries[key] = (tokens - 1, now)
            if len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)


RATE_LIMITER = RateLimiter()


class GameHandler(BaseHTTPRequestHandler):
    server_version = "OrbitaGame"

    def version_string(self):
        return "Orbita"

    def send_security_headers(self, nonce=None):
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in SECURITY_HEADERS.items():
            if name == "Content-Security-Policy" and nonce:
                value = value.replace(
                    "script-src 'self'",
                    f"script-src 'self' 'nonce-{nonce}'",
                ).replace(
                    "style-src 'self'",
                    f"style-src 'self' 'nonce-{nonce}'",
                )
            self.send_header(name, value)
        if PUBLIC_SCHEME == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def send_json(self, status, payload, session_cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        if session_cookie is not None:
            self.send_header("Set-Cookie", session_cookie)
        retry_after = getattr(self, "retry_after", None)
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        self.end_headers()
        self.wfile.write(body)

    def send_download(self, content_type, filename, body):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        content_lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") is not None or len(content_lengths) != 1:
            raise RequestError(400, "El contenido de la solicitud no es válido.")
        raw_length = content_lengths[0]
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise RequestError(400, "Solicitud no válida.")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise RequestError(400, "Solicitud no válida.") from error
        if length < 1 or length > MAX_BODY_BYTES:
            raise RequestError(400, "El contenido de la solicitud no es válido.")
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
            raise RequestError(400, "El contenido de la solicitud no es válido.") from error
        if not isinstance(payload, dict):
            raise RequestError(400, "El contenido de la solicitud no es válido.")
        return payload

    def send_error_json(self, error):
        self.retry_after = error.retry_after
        try:
            self.send_json(error.status, {"error": error.message})
        finally:
            self.retry_after = None

    def validate_same_origin_json_request(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(415, "El contenido de la solicitud debe ser JSON.")

        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if not origin or not host:
            raise RequestError(403, "La solicitud no tiene un origen permitido.")
        try:
            parsed_origin = urlparse(origin)
            parsed_host = urlparse(f"//{host}")
            origin_port = parsed_origin.port
            host_port = parsed_host.port
        except ValueError as error:
            raise RequestError(403, "La solicitud no tiene un origen permitido.") from error
        if origin_port is None:
            origin_port = 443 if parsed_origin.scheme == "https" else 80
        if host_port is None:
            host_port = 443 if parsed_origin.scheme == "https" else 80
        if (
            parsed_origin.scheme != PUBLIC_SCHEME
            or not parsed_origin.hostname
            or parsed_origin.username is not None
            or parsed_origin.password is not None
            or parsed_origin.path not in ("", "/")
            or parsed_origin.query
            or parsed_origin.fragment
            or not parsed_host.hostname
            or parsed_host.username is not None
            or parsed_host.password is not None
            or parsed_host.path
            or parsed_host.query
            or parsed_host.fragment
            or parsed_origin.hostname.casefold() != parsed_host.hostname.casefold()
            or origin_port != host_port
        ):
            raise RequestError(403, "La solicitud no tiene un origen permitido.")

    def rate_limit_client_ip(self):
        peer_ip = ipaddress.ip_address(self.client_address[0])
        if not any(peer_ip in network for network in TRUSTED_PROXY_NETWORKS):
            return str(peer_ip)
        forwarded_for = self.headers.get("X-Forwarded-For", "")
        if not forwarded_for or len(forwarded_for) > 64:
            raise RequestError(400, "La dirección de origen no es válida.")
        try:
            return str(ipaddress.ip_address(forwarded_for.split(",", 1)[0].strip()))
        except ValueError as error:
            raise RequestError(400, "La dirección de origen no es válida.") from error

    def enforce_rate_limit(self, path):
        limit_config = RATE_LIMITS.get(path)
        if limit_config is None:
            return
        limit, period = limit_config
        client_ip = self.rate_limit_client_ip()
        RATE_LIMITER.check((path, client_ip), limit, period)

    @staticmethod
    def session_cookie(token, max_age):
        name = "__Host-orbita_session" if PUBLIC_SCHEME == "https" else "orbita_session"
        attributes = [
            f"{name}={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={max_age}",
        ]
        if PUBLIC_SCHEME == "https":
            attributes.append("Secure")
        return "; ".join(attributes)

    def session_token(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return ""
        name = "__Host-orbita_session" if PUBLIC_SCHEME == "https" else "orbita_session"
        cookie = cookies.get(name)
        token = cookie.value if cookie is not None else ""
        return token if re.fullmatch(r"[A-Za-z0-9_-]{43}", token) else ""

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            self.enforce_rate_limit(path)
            if path == "/api/me":
                user = self.authenticated_user()
                self.send_json(200, {"user": {"username": user["username"]}})
            elif path == "/api/me/export.xlsx":
                self.export_personal_games()
            elif path == "/api/leaderboard":
                with database() as connection:
                    rows = connection.execute(
                        """
                        SELECT users.username, MAX(games.score) AS score
                        FROM games JOIN users ON users.id = games.user_id
                        GROUP BY users.id
                        ORDER BY score DESC, users.username COLLATE NOCASE ASC
                        LIMIT 10
                        """
                    ).fetchall()
                self.send_json(
                    200,
                    {
                        "ranking": [
                            {"position": index, "username": row["username"], "score": row["score"]}
                            for index, row in enumerate(rows, start=1)
                        ]
                    },
                )
            elif path == "/":
                self.serve_index()
            elif path in STATIC_FILES:
                relative_path, content_type, cache_control = STATIC_FILES[path]
                self.serve_file(relative_path, content_type, cache_control)
            else:
                self.send_json(404, {"error": "No se encontró la página."})
        except RequestError as error:
            self.send_error_json(error)
        except sqlite3.Error as error:
            self.log_error("Database error: %s", error)
            self.send_json(500, {"error": "No se pudo consultar la base de datos."})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path in (
                "/api/auth/code",
                "/api/auth/verify",
                "/api/logout",
                "/api/games/start",
                "/api/games",
                "/api/shutdown",
            ):
                self.validate_same_origin_json_request()
            self.enforce_rate_limit(path)
            payload = self.read_json()
            if path == "/api/auth/code":
                self.request_email_code(payload)
            elif path == "/api/auth/verify":
                self.verify_email_code(payload)
            elif path == "/api/logout":
                self.logout()
            elif path == "/api/games/start":
                self.start_game_run()
            elif path == "/api/games":
                self.record_game(payload)
            elif path == "/api/shutdown":
                self.shutdown_local_game()
            else:
                self.send_json(404, {"error": "No se encontró la página."})
        except RequestError as error:
            self.send_error_json(error)
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "El nombre de usuario o el correo ya está registrado."})
        except sqlite3.Error as error:
            self.log_error("Database error: %s", error)
            self.send_json(500, {"error": "No se pudo guardar la información."})

    def serve_index(self):
        self.serve_file("index.html", "text/html; charset=utf-8", "no-cache")

    def serve_file(self, relative_path, content_type, cache_control):
        try:
            body = (ROOT / relative_path).read_bytes()
        except OSError as error:
            self.log_error("Could not read %s: %s", relative_path, error)
            self.send_json(500, {"error": "No se pudo abrir el juego."})
            return
        nonce = None
        if relative_path == "index.html":
            nonce = secrets.token_urlsafe(18)
            html = body.decode("utf-8")
            html = re.sub(
                r"<(script|style)(?=[\s>])",
                lambda match: f'<{match.group(1)} nonce="{nonce}"',
                html,
                flags=re.IGNORECASE,
            )
            body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.send_security_headers(nonce)
        self.end_headers()
        self.wfile.write(body)

    def legacy_credentials(self, username, password):
        if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
            username = ""
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            password = ""
        with database() as connection:
            user = connection.execute(
                """
                SELECT id, username, email, password_hash, password_salt
                FROM users WHERE username = ?
                """,
                (username,),
            ).fetchone()
        salt = user["password_salt"] if user is not None else LEGACY_LINK_DUMMY_SALT
        expected_hash = user["password_hash"] if user is not None else LEGACY_LINK_DUMMY_HASH
        supplied_hash = password_digest(password, salt)
        valid = hmac.compare_digest(supplied_hash, expected_hash)
        return user if valid and user is not None else None

    def request_email_code(self, payload):
        purpose = payload.get("purpose")
        if purpose not in ("register", "login", "link"):
            raise RequestError(400, "La solicitud de acceso no es válida.")
        email = normalize_email(payload.get("email"))
        address_key = hashlib.sha256(email.encode("utf-8")).hexdigest()
        RATE_LIMITER.check(("email-code-address", address_key), EMAIL_CODE_MAX_PER_ADDRESS, 60 * 60)

        username = None
        user = None
        eligible = False
        if purpose == "register":
            username = payload.get("username")
            if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
                raise RequestError(400, "El usuario debe tener de 3 a 20 caracteres: letras, números o _.")
            with database() as connection:
                username_exists = connection.execute(
                    "SELECT 1 FROM users WHERE username = ?", (username,)
                ).fetchone()
                email_exists = connection.execute(
                    "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)
                ).fetchone()
            if username_exists is not None:
                raise RequestError(409, "Ese nombre de usuario ya está registrado.")
            if email_exists is not None:
                raise RequestError(409, "Ese correo ya está vinculado a una cuenta.")
            eligible = True
        elif purpose == "login":
            with database() as connection:
                user = connection.execute(
                    "SELECT id, username FROM users WHERE email = ? COLLATE NOCASE",
                    (email,),
                ).fetchone()
            eligible = user is not None
        else:
            username = payload.get("username")
            password = payload.get("password")
            user = self.legacy_credentials(username, password)
            if user is None:
                raise RequestError(400, "El usuario o la contraseña de la cuenta anterior no son válidos.")
            if user["email"] is not None:
                raise RequestError(409, "Esta cuenta ya tiene un correo vinculado.")
            with database() as connection:
                email_exists = connection.execute(
                    "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)
                ).fetchone()
            if email_exists is not None:
                raise RequestError(409, "Ese correo ya está vinculado a una cuenta.")
            eligible = True

        challenge_id = secrets.token_urlsafe(24)
        if eligible:
            code = f"{secrets.randbelow(100_000_000):08d}"
            now = int(time.time())
            try:
                with database() as connection:
                    connection.execute(
                        """
                        DELETE FROM email_code_challenges
                        WHERE email = ? COLLATE NOCASE AND purpose = ?
                        """,
                        (email, purpose),
                    )
                    connection.execute(
                        """
                        DELETE FROM email_code_challenges WHERE expires_at <= ?
                        """,
                        (now,),
                    )
                    connection.execute(
                        """
                        INSERT INTO email_code_challenges (
                            challenge_id, purpose, email, user_id, username, code_hash,
                            attempts, expires_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                        """,
                        (
                            challenge_id,
                            purpose,
                            email,
                            user["id"] if user is not None else None,
                            username,
                            email_code_digest(challenge_id, code),
                            now + EMAIL_CODE_SECONDS,
                            now,
                        ),
                    )
                try:
                    send_email_code(email, code)
                except (OSError, RuntimeError, smtplib.SMTPException, ValueError) as error:
                    with database() as connection:
                        connection.execute(
                            "DELETE FROM email_code_challenges WHERE challenge_id = ?",
                            (challenge_id,),
                        )
                    self.log_error("Could not send sign-in code: %s", error)
                    raise RequestError(
                        503,
                        "No se pudo enviar el código. Revisa la configuración del correo del servidor.",
                    ) from error
            except sqlite3.IntegrityError:
                if purpose == "register":
                    raise RequestError(
                        409, "El nombre de usuario o el correo ya está registrado."
                    )
                eligible = False

        self.send_json(
            202,
            {
                "challengeId": challenge_id,
                "message": "Si los datos corresponden a una cuenta válida, recibirás un código por correo.",
            },
        )

    def verify_email_code(self, payload):
        challenge_id = payload.get("challengeId")
        code = payload.get("code")
        if (
            not isinstance(challenge_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{32}", challenge_id)
            or not isinstance(code, str)
            or not re.fullmatch(r"[0-9]{8}", code)
        ):
            raise RequestError(400, "El código no es válido o venció.")

        with database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            challenge = connection.execute(
                "SELECT * FROM email_code_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            now = int(time.time())
            if (
                challenge is None
                or challenge["expires_at"] <= now
                or challenge["attempts"] >= EMAIL_CODE_ATTEMPTS
            ):
                if challenge is not None:
                    connection.execute(
                        "DELETE FROM email_code_challenges WHERE challenge_id = ?",
                        (challenge_id,),
                    )
                invalid = True
            elif not hmac.compare_digest(
                bytes(challenge["code_hash"]), email_code_digest(challenge_id, code)
            ):
                attempts = challenge["attempts"] + 1
                if attempts >= EMAIL_CODE_ATTEMPTS:
                    connection.execute(
                        "DELETE FROM email_code_challenges WHERE challenge_id = ?",
                        (challenge_id,),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE email_code_challenges SET attempts = ?
                        WHERE challenge_id = ?
                        """,
                        (attempts, challenge_id),
                    )
                invalid = True
            else:
                connection.execute(
                    "DELETE FROM email_code_challenges WHERE challenge_id = ?",
                    (challenge_id,),
                )
                invalid = False
                user_id = challenge["user_id"]
                username = challenge["username"]
                if challenge["purpose"] == "register":
                    salt = secrets.token_bytes(16)
                    password_hash = password_digest(secrets.token_urlsafe(32), salt)
                    created_at = datetime.now(timezone.utc).isoformat()
                    cursor = connection.execute(
                        """
                        INSERT INTO users (
                            username, email, password_hash, password_salt, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (username, challenge["email"], password_hash, salt, created_at),
                    )
                    user_id = cursor.lastrowid
                elif challenge["purpose"] == "login":
                    user = connection.execute(
                        """
                        SELECT id, username FROM users
                        WHERE id = ? AND email = ? COLLATE NOCASE
                        """,
                        (user_id, challenge["email"]),
                    ).fetchone()
                    if user is None:
                        invalid = True
                    else:
                        username = user["username"]
                elif challenge["purpose"] == "link":
                    cursor = connection.execute(
                        """
                        UPDATE users SET email = ?
                        WHERE id = ? AND email IS NULL
                        """,
                        (challenge["email"], user_id),
                    )
                    if cursor.rowcount != 1:
                        invalid = True

        if invalid:
            raise RequestError(400, "El código no es válido o venció.")
        self.create_session(user_id, username)

    def create_session(self, user_id, username):
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + SESSION_SECONDS
        with database() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_digest(token), user_id, expires_at),
            )
        self.send_json(
            200,
            {"user": {"username": username}, "expiresAt": expires_at},
            self.session_cookie(token, SESSION_SECONDS),
        )

    def authenticated_user(self):
        token = self.session_token()
        if not token:
            raise RequestError(401, "Inicia sesión para continuar.")
        with database() as connection:
            user = connection.execute(
                """
                SELECT users.id, users.username
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_digest(token), int(time.time())),
            ).fetchone()
        if user is None:
            raise RequestError(401, "Tu sesión venció. Inicia sesión de nuevo.")
        return user

    def logout(self):
        token = self.session_token()
        if token:
            with database() as connection:
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),)
                )
        self.send_json(200, {"ok": True}, self.session_cookie("", 0))

    def start_game_run(self):
        user = self.authenticated_user()
        run_id = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = int(now) + 86_400
        with database() as connection:
            connection.execute("DELETE FROM game_runs WHERE expires_at <= ?", (int(now),))
            connection.execute("DELETE FROM game_runs WHERE user_id = ?", (user["id"],))
            connection.execute(
                """
                INSERT INTO game_runs (run_hash, user_id, started_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_digest(run_id), user["id"], now, expires_at),
            )
        self.send_json(201, {"runId": run_id})

    def record_game(self, payload):
        user = self.authenticated_user()
        run_id = payload.get("runId")
        score = payload.get("score")
        duration = payload.get("durationSeconds")
        if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", run_id):
            raise RequestError(400, "No se pudo verificar el inicio de la partida.")
        if type(score) is not int or not 0 <= score <= 1_000_000:
            raise RequestError(400, "La puntuación no es válida.")
        if type(duration) is not int or not 0 <= duration <= 86_400:
            raise RequestError(400, "La duración no es válida.")
        if not duration * 10 <= score < (duration + 1) * 10:
            raise RequestError(400, "La puntuación no coincide con la duración de la partida.")
        played_at = datetime.now(timezone.utc).isoformat()
        with database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = connection.execute(
                """
                SELECT started_at FROM game_runs
                WHERE run_hash = ? AND user_id = ? AND expires_at > ?
                """,
                (token_digest(run_id), user["id"], int(time.time())),
            ).fetchone()
            if run is None:
                raise RequestError(400, "La partida no existe, venció o ya fue registrada.")
            elapsed = max(0, time.time() - run["started_at"])
            if duration > int(elapsed) or score > int(elapsed * 10):
                raise RequestError(400, "La puntuación supera el tiempo de juego verificado.")
            connection.execute(
                "DELETE FROM game_runs WHERE run_hash = ?", (token_digest(run_id),)
            )
            cursor = connection.execute(
                """
                INSERT INTO games (user_id, score, duration_seconds, played_at)
                VALUES (?, ?, ?, ?)
                """,
                (user["id"], score, duration, played_at),
            )
        self.send_json(201, {"saved": True, "gameId": cursor.lastrowid})

    def export_personal_games(self):
        user = self.authenticated_user()
        with database() as connection:
            games = connection.execute(
                """
                SELECT score, duration_seconds, played_at
                FROM games
                WHERE user_id = ?
                ORDER BY score DESC, played_at DESC, id DESC
                """,
                (user["id"],),
            ).fetchall()
        workbook = build_personal_workbook(user["username"], games)
        self.send_download(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "orbita-mis-partidas.xlsx",
            workbook,
        )

    def shutdown_local_game(self):
        if HOST not in ("127.0.0.1", "localhost", "::1"):
            self.send_json(404, {"error": "No se encontró la página."})
            return
        try:
            is_local = ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            is_local = False
        if not is_local:
            self.send_json(403, {"error": "Solo puedes cerrar el juego desde esta computadora."})
            return
        self.send_json(200, {"ok": True})
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, format_string, *args):
        if not urlparse(self.path).path.startswith("/api/"):
            super().log_message(format_string, *args)


def main():
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), GameHandler)
    print(f"Órbita disponible en http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
