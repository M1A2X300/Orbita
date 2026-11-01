import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8000"))
URL = f"http://{HOST}:{PORT}/?managed=1"
STARTUP_TIMEOUT = 15


def find_browser():
    paths = []
    for variable, suffix in (
        ("PROGRAMFILES(X86)", Path("Microsoft") / "Edge" / "Application" / "msedge.exe"),
        ("PROGRAMFILES", Path("Microsoft") / "Edge" / "Application" / "msedge.exe"),
        ("PROGRAMFILES(X86)", Path("Google") / "Chrome" / "Application" / "chrome.exe"),
        ("PROGRAMFILES", Path("Google") / "Chrome" / "Application" / "chrome.exe"),
        ("LOCALAPPDATA", Path("Microsoft") / "Edge" / "Application" / "msedge.exe"),
        ("LOCALAPPDATA", Path("Google") / "Chrome" / "Application" / "chrome.exe"),
    ):
        base = os.environ.get(variable)
        if base:
            paths.append(Path(base) / suffix)
    for path in paths:
        if path.is_file():
            return str(path)
    for command in ("msedge.exe", "chrome.exe"):
        browser = shutil.which(command)
        if browser:
            return browser
    raise RuntimeError("No encontré Microsoft Edge o Google Chrome para abrir el juego.")


def wait_for_server(server):
    deadline = time.monotonic() + STARTUP_TIMEOUT
    last_error = "El servidor todavía no responde."
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"El servidor terminó con código {server.returncode}.")
        try:
            with urllib.request.urlopen(f"http://{HOST}:{PORT}/api/leaderboard", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as error:
            last_error = str(error)
        time.sleep(0.25)
    raise RuntimeError(f"El servidor no inició en {HOST}:{PORT}: {last_error}")


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


def stop_process(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def find_server_python():
    interpreter = Path(sys.executable)
    if interpreter.name.lower() == "pythonw.exe":
        console_interpreter = interpreter.with_name("python.exe")
        if console_interpreter.is_file():
            return str(console_interpreter)
    return sys.executable


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments in (["--help"], ["-h"]):
        print("Uso: iniciar_juego.py [--diagnostico]")
        return 0
    diagnostic = arguments == ["--diagnostico"]
    if arguments and not diagnostic:
        print("Uso: iniciar_juego.py [--diagnostico]")
        return 2

    server = None
    browser = None
    try:
        environment = os.environ.copy()
        environment["ORBITA_HOST"] = HOST
        environment["PORT"] = str(PORT)
        no_console_window = 0 if diagnostic else getattr(subprocess, "CREATE_NO_WINDOW", 0)
        server_command = [find_server_python(), str(ROOT / "servidor.py")]
        if diagnostic:
            print(f"Comando del servidor: {subprocess.list2cmdline(server_command)}", flush=True)
        server = subprocess.Popen(
            server_command,
            cwd=ROOT,
            env=environment,
            creationflags=no_console_window,
            stdin=subprocess.DEVNULL,
            stdout=None if diagnostic else subprocess.DEVNULL,
            stderr=None if diagnostic else subprocess.DEVNULL,
        )
        wait_for_server(server)
        if diagnostic:
            print(f"Servidor iniciado (PID {server.pid}).", flush=True)

        profile = Path(
            os.environ.get(
                "ORBITA_APP_PROFILE",
                Path(os.environ.get("LOCALAPPDATA", ROOT)) / "Orbita" / "BrowserProfile",
            )
        )
        profile.mkdir(parents=True, exist_ok=True)
        browser_command = [
            find_browser(),
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            f"--app={URL}",
        ]
        if diagnostic:
            print(f"Comando del navegador: {subprocess.list2cmdline(browser_command)}", flush=True)
        browser = subprocess.Popen(
            browser_command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=None if diagnostic else subprocess.DEVNULL,
            stderr=None if diagnostic else subprocess.DEVNULL,
            creationflags=no_console_window,
        )
        if diagnostic:
            print(f"Navegador iniciado (PID {browser.pid}).", flush=True)

        while browser.poll() is None and server.poll() is None:
            time.sleep(0.25)
    except (OSError, RuntimeError) as error:
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None,
                f"No se pudo iniciar Órbita:\n{error}",
                "Órbita",
                0x10,
            )
        except (AttributeError, OSError):
            if sys.stderr is not None:
                print(f"No se pudo iniciar Órbita: {error}", file=sys.stderr)
        return 1
    finally:
        if server is not None and server.poll() is None:
            if diagnostic:
                print("Deteniendo el servidor...", flush=True)
            request_shutdown()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stop_process(server)
        if browser is not None and browser.poll() is None:
            if diagnostic:
                print("Deteniendo el navegador...", flush=True)
            stop_process(browser)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
