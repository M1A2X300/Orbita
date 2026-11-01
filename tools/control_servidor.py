import getpass
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8000"))
ADMIN_PASSWORD_ITERATIONS = 310_000


def admin_credential_path():
    profile = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return profile / "Orbita" / "admin-credential.json"


def derive_admin_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ADMIN_PASSWORD_ITERATIONS
    )


def setup_admin_password():
    try:
        password = getpass.getpass(
            "Nueva contraseña de administrador (12 caracteres mínimo): "
        )
        confirmation = getpass.getpass("Confirma la contraseña: ")
    except (EOFError, KeyboardInterrupt):
        print("\nConfiguración cancelada.")
        return 1
    if len(password) < 12:
        print("La contraseña debe tener al menos 12 caracteres.")
        return 1
    if password != confirmation:
        print("Las contraseñas no coinciden.")
        return 1

    salt = secrets.token_bytes(16)
    credential = {
        "version": 1,
        "iterations": ADMIN_PASSWORD_ITERATIONS,
        "salt": salt.hex(),
        "passwordHash": derive_admin_password(password, salt).hex(),
    }
    path = admin_credential_path()
    temporary_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path.write_text(json.dumps(credential), encoding="utf-8")
        os.replace(temporary_path, path)
    except OSError as error:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        print(f"No se pudo guardar la contraseña local: {error}")
        return 1
    print("Contraseña privada guardada en el perfil local de Windows.")
    return 0


def verify_admin_password():
    path = admin_credential_path()
    try:
        credential = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(credential, dict)
            or credential.get("version") != 1
            or credential.get("iterations") != ADMIN_PASSWORD_ITERATIONS
        ):
            raise ValueError("formato no válido")
        salt = bytes.fromhex(credential["salt"])
        expected_hash = bytes.fromhex(credential["passwordHash"])
        if len(salt) != 16 or len(expected_hash) != 32:
            raise ValueError("longitud no válida")
    except FileNotFoundError:
        print("Configura primero una contraseña con --setup-admin.")
        return False
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ):
        print("No se pudo leer la contraseña local. Vuelve a configurarla con --setup-admin.")
        return False

    try:
        password = getpass.getpass("Contraseña de administrador: ")
    except (EOFError, KeyboardInterrupt):
        print("\nOperación cancelada.")
        return False
    if not hmac.compare_digest(derive_admin_password(password, salt), expected_hash):
        print("Contraseña incorrecta.")
        return False
    return True


def request_shutdown():
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/api/shutdown",
        data=b"{}",
        headers={
            "Content-Type": "application/json",
            "Origin": f"http://{HOST}:{PORT}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2):
            return True
    except (OSError, urllib.error.URLError):
        return False


def wait_for_server_shutdown():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection((HOST, PORT), timeout=0.5)
        except ConnectionRefusedError:
            return True
        except OSError:
            return False
        else:
            connection.close()
        time.sleep(0.1)
    return False


def stop_server_command():
    if not verify_admin_password():
        return 1
    try:
        answer = input("¿Apagar el servidor local de Órbita? [s/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nOperación cancelada.")
        return 1
    if answer not in ("s", "si", "sí"):
        print("Operación cancelada.")
        return 0
    if not request_shutdown():
        print("No se pudo apagar el servidor. ¿Está Órbita abierta en esta PC?")
        return 1
    if not wait_for_server_shutdown():
        print("El servidor recibió la orden, pero sigue respondiendo.")
        return 1
    print("Servidor apagado. Para iniciarlo de nuevo, abre Órbita.")
    return 0


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--setup-admin"]:
        return setup_admin_password()
    if arguments == ["--stop-server"]:
        return stop_server_command()
    if arguments in (["--help"], ["-h"]):
        print("Uso: control_servidor.py [--setup-admin | --stop-server]")
        return 0
    print("Uso: control_servidor.py [--setup-admin | --stop-server]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
