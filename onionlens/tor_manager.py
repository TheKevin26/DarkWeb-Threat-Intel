"""Run a headless Tor client for the crawler.

Uses the ``tor.exe`` shipped inside Tor Browser (or any tor binary on PATH / ONIONLENS_TOR_EXE) with
its own data directory under ./data/tor, listening on 127.0.0.1:9050 only. No browser window is opened.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .config import ROOT

log = logging.getLogger(__name__)

TOR_DIR = ROOT / "data" / "tor"


def find_tor_exe() -> Path | None:
    candidates = [
        os.environ.get("ONIONLENS_TOR_EXE"),
        shutil.which("tor"),
        Path.home() / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(os.environ.get("ProgramFiles", "")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path("/usr/bin/tor"),
        Path("/usr/local/bin/tor"),
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


def port_open(port: int = 9050, host: str = "127.0.0.1") -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def start_tor(port: int = 9050, wait_seconds: int = 90) -> dict:
    """Start tor in the background if nothing is listening yet. Returns {started, running, exe, log}."""
    if port_open(port):
        return {"started": False, "running": True, "exe": None, "message": f"something already listens on {port}"}
    exe = find_tor_exe()
    if not exe:
        return {"started": False, "running": False, "exe": None, "message": "tor binary not found (install Tor Browser)"}
    TOR_DIR.mkdir(parents=True, exist_ok=True)
    torrc = TOR_DIR / "torrc"
    logfile = TOR_DIR / "tor.log"
    torrc.write_text(
        f"SocksPort 127.0.0.1:{port}\n"
        f"DataDirectory {(TOR_DIR / 'state').as_posix()}\n"
        f"Log notice file {logfile.as_posix()}\n"
        "ClientOnly 1\n",
        encoding="utf-8",
    )
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(
        [str(exe), "-f", str(torrc)],
        cwd=str(exe.parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
        start_new_session=os.name != "nt",
    )
    deadline = time.time() + wait_seconds
    bootstrapped = False
    while time.time() < deadline:
        if logfile.exists() and "Bootstrapped 100%" in logfile.read_text(encoding="utf-8", errors="ignore"):
            bootstrapped = True
            break
        time.sleep(2)
    log.info("tor started from %s (bootstrapped=%s)", exe, bootstrapped)
    return {"started": True, "running": port_open(port), "bootstrapped": bootstrapped, "exe": str(exe), "log": str(logfile)}
