# warp_manager.py
# Optional Cloudflare WARP exit via userspace wireproxy (SOCKS5 on 127.0.0.1).
# Direct panel traffic never touches this module unless an inbound has use_warp=True.
#
# Design:
# - Non-root, no TUN / NET_ADMIN
# - Auto-download wireproxy binary, auto-register WARP via Cloudflare client API
# - Health probe through SOCKS; auto-restart after consecutive failures
# - Fail-closed for use_warp inbounds when process is down

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import platform
import secrets
import socket
import struct
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.request import Request, urlopen

logger = logging.getLogger("warp_manager")

# ── Paths / constants ──────────────────────────────────────────────────────
WARP_DIR = Path(os.environ.get("WARP_DATA_DIR") or (
    "/data/warp" if os.path.isdir("/data") else str(Path(__file__).resolve().parent / "warp_data")
))
WIREPROXY_BIN = WARP_DIR / "wireproxy"
WG_CONF = WARP_DIR / "wireproxy.conf"
ACCOUNT_JSON = WARP_DIR / "account.json"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = int(os.environ.get("WARP_SOCKS_PORT", "10808"))
HEALTH_INTERVAL_S = 45
HEALTH_FAIL_THRESHOLD = 3  # consecutive fails before auto-restart
HEALTH_URL = "https://www.cloudflare.com/cdn-cgi/trace"
CF_API = "https://api.cloudflareclient.com/v0a2158"
WIREPROXY_RELEASE_API = "https://api.github.com/repos/pufferffish/wireproxy/releases/latest"
# Known Cloudflare WARP peer public key (stable across free accounts)
WARP_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT = "engage.cloudflareclient.com:2408"

_state: dict[str, Any] = {
    "enabled": False,       # user intent from settings
    "running": False,       # process believed up
    "socks_ok": False,      # last health probe through SOCKS
    "last_error": "",
    "last_ok_at": 0.0,
    "fail_streak": 0,
    "proc": None,           # subprocess.Popen | None
    "binary_ready": False,
    "config_ready": False,
    "restarts": 0,
}
_lock = asyncio.Lock()
_health_task: Optional[asyncio.Task] = None


def get_status() -> dict:
    """Snapshot for API / dashboard (no secrets)."""
    return {
        "enabled": bool(_state["enabled"]),
        "running": bool(_state["running"]) and _proc_alive(),
        "socks_ok": bool(_state["socks_ok"]),
        "last_error": str(_state.get("last_error") or ""),
        "binary_ready": bool(_state["binary_ready"]) or WIREPROXY_BIN.is_file(),
        "config_ready": bool(_state["config_ready"]) or WG_CONF.is_file(),
        "socks": f"{SOCKS_HOST}:{SOCKS_PORT}",
        "restarts": int(_state.get("restarts") or 0),
        "last_ok_at": _state.get("last_ok_at") or 0,
    }


def _proc_alive() -> bool:
    p = _state.get("proc")
    if p is None:
        return False
    return p.poll() is None


# ── X25519 keygen (stdlib-only via OS; fallback pure-ish) ───────────────────
def _b64_key(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _generate_wg_keypair() -> tuple[str, str]:
    """Return (private_b64, public_b64) for WireGuard/X25519."""
    # Prefer cryptography if present
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = X25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64_key(priv_raw), _b64_key(pub_raw)
    except Exception:
        pass
    # PyNaCl
    try:
        from nacl.bindings import crypto_scalarmult_base
        priv_raw = secrets.token_bytes(32)
        # clamp as per X25519
        priv_list = list(priv_raw)
        priv_list[0] &= 248
        priv_list[31] &= 127
        priv_list[31] |= 64
        priv_raw = bytes(priv_list)
        pub_raw = crypto_scalarmult_base(priv_raw)
        return _b64_key(priv_raw), _b64_key(pub_raw)
    except Exception:
        pass
    # openssl fallback
    try:
        out = subprocess.check_output(
            ["openssl", "genpkey", "-algorithm", "X25519"],
            stderr=subprocess.DEVNULL,
        )
        # parse DER is painful; use pkey -text
        text = subprocess.check_output(
            ["openssl", "pkey", "-text", "-noout"],
            input=out,
            stderr=subprocess.DEVNULL,
        ).decode()
        # This path is best-effort; prefer nacl/cryptography in requirements
        raise RuntimeError("openssl text parse not implemented; install PyNaCl")
    except Exception as e:
        raise RuntimeError(
            "Need PyNaCl or cryptography for WARP keygen. "
            f"Install: pip install PyNaCl ({e})"
        ) from e


def _http_json(method: str, url: str, body: dict | None = None, token: str | None = None) -> dict:
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
        "CF-Client-Version": "a-6.10-2158",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def register_warp_account(force: bool = False) -> dict:
    """
    Register a free WARP device via Cloudflare client API and write wireproxy conf.
    Returns public account metadata (no private key in return value).
    """
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    if ACCOUNT_JSON.is_file() and WG_CONF.is_file() and not force:
        _state["config_ready"] = True
        return {"ok": True, "reused": True}

    private_key, public_key = _generate_wg_keypair()
    tos = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    install_id = secrets.token_urlsafe(22)[:22]
    body = {
        "key": public_key,
        "install_id": install_id,
        "fcm_token": "",
        "tos": tos,
        "type": "Android",
        "model": "PC",
        "locale": "en_US",
    }
    result = _http_json("POST", f"{CF_API}/reg", body)
    device_id = result.get("id")
    token = result.get("token")
    if not device_id or not token:
        raise RuntimeError(f"WARP register failed: {result}")

    # Enable WARP on the device
    try:
        _http_json("PATCH", f"{CF_API}/reg/{device_id}", {"warp_enabled": True}, token=token)
    except Exception as e:
        logger.warning(f"warp_enabled patch: {e}")

    # Fetch full config
    cfg = _http_json("GET", f"{CF_API}/reg/{device_id}", token=token)
    iface = (cfg.get("config") or {}).get("interface") or {}
    peers = (cfg.get("config") or {}).get("peers") or []
    peer = peers[0] if peers else {}
    addresses = iface.get("addresses") or {}
    v4 = addresses.get("v4") or "172.16.0.2"
    v6 = addresses.get("v6") or ""
    peer_pub = peer.get("public_key") or WARP_PEER_PUBLIC_KEY
    endpoint = (peer.get("endpoint") or {}).get("host") or WARP_ENDPOINT
    if ":" not in str(endpoint):
        endpoint = f"{endpoint}:2408"
    client_id = (cfg.get("config") or {}).get("client_id") or ""

    addr_line = f"{v4}/32"
    if v6:
        addr_line = f"{v4}/32, {v6}/128"

    conf = f"""# Auto-generated WARP profile for Luffy Panel (wireproxy)
[Interface]
PrivateKey = {private_key}
Address = {addr_line}
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {peer_pub}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[Socks5]
BindAddress = {SOCKS_HOST}:{SOCKS_PORT}
"""
    WG_CONF.write_text(conf, encoding="utf-8")
    ACCOUNT_JSON.write_text(json.dumps({
        "id": device_id,
        "account": (result.get("account") or {}),
        "client_id": client_id,
        "endpoint": endpoint,
        "v4": v4,
        "v6": v6,
        "created_at": tos,
    }, indent=2), encoding="utf-8")
    _state["config_ready"] = True
    _state["last_error"] = ""
    logger.info(f"WARP account registered device_id={device_id}")
    return {"ok": True, "reused": False, "device_id": device_id}


def _arch_asset_name() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "wireproxy_linux_amd64.tar.gz"
    if machine in ("aarch64", "arm64"):
        return "wireproxy_linux_arm64.tar.gz"
    if machine.startswith("arm"):
        return "wireproxy_linux_arm.tar.gz"
    return "wireproxy_linux_amd64.tar.gz"


def ensure_wireproxy_binary() -> Path:
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    if WIREPROXY_BIN.is_file() and os.access(WIREPROXY_BIN, os.X_OK):
        _state["binary_ready"] = True
        return WIREPROXY_BIN

    asset_name = _arch_asset_name()
    logger.info(f"Downloading wireproxy ({asset_name})…")
    req = Request(
        WIREPROXY_RELEASE_API,
        headers={"User-Agent": "LuffyPanel-WARP/1.0", "Accept": "application/vnd.github+json"},
    )
    with urlopen(req, timeout=60) as resp:
        release = json.loads(resp.read().decode())
    assets = release.get("assets") or []
    url = None
    for a in assets:
        if a.get("name") == asset_name:
            url = a.get("browser_download_url")
            break
    if not url:
        # fallback fixed tag path
        url = f"https://github.com/pufferffish/wireproxy/releases/latest/download/{asset_name}"

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / asset_name
        with urlopen(Request(url, headers={"User-Agent": "LuffyPanel-WARP/1.0"}), timeout=120) as r, open(tar_path, "wb") as f:
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
        with tarfile.open(tar_path, "r:gz") as tar:
            member = None
            for m in tar.getmembers():
                if m.isfile() and (m.name.endswith("wireproxy") or m.name.split("/")[-1] == "wireproxy"):
                    member = m
                    break
            if member is None:
                raise RuntimeError("wireproxy binary not found in archive")
            member.name = "wireproxy"  # extract flat
            tar.extract(member, path=tmp)
        src = Path(tmp) / "wireproxy"
        if not src.is_file():
            # nested path
            for p in Path(tmp).rglob("wireproxy"):
                if p.is_file():
                    src = p
                    break
        data = src.read_bytes()
        WIREPROXY_BIN.write_bytes(data)
        WIREPROXY_BIN.chmod(0o755)

    _state["binary_ready"] = True
    logger.info(f"wireproxy installed at {WIREPROXY_BIN}")
    return WIREPROXY_BIN


def _stop_proc():
    p = _state.get("proc")
    if p is None:
        _state["running"] = False
        return
    try:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
    except Exception as e:
        logger.warning(f"stop wireproxy: {e}")
    _state["proc"] = None
    _state["running"] = False
    _state["socks_ok"] = False


def _start_proc() -> None:
    _stop_proc()
    ensure_wireproxy_binary()
    if not WG_CONF.is_file():
        register_warp_account(force=False)
    if not WG_CONF.is_file():
        raise RuntimeError("WARP config missing after register")
    log_path = WARP_DIR / "wireproxy.log"
    log_f = open(log_path, "ab")
    p = subprocess.Popen(
        [str(WIREPROXY_BIN), "-c", str(WG_CONF), "-s"],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=str(WARP_DIR),
        start_new_session=True,
    )
    _state["proc"] = p
    _state["running"] = True
    time.sleep(1.2)
    if p.poll() is not None:
        _state["running"] = False
        tail = ""
        try:
            tail = log_path.read_text(encoding="utf-8", errors="ignore")[-800:]
        except Exception:
            pass
        raise RuntimeError(f"wireproxy exited immediately (code={p.returncode}). {tail}")


async def open_socks_connection(address: str, port: int, timeout: float = 10.0):
    """
    asyncio StreamReader/Writer via local SOCKS5 CONNECT (no auth).
    Used only when use_warp=True.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(SOCKS_HOST, SOCKS_PORT), timeout=timeout
    )
    try:
        # greeting: ver=5, 1 method, no-auth
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != 5 or resp[1] != 0:
            raise OSError(f"SOCKS5 auth rejected: {resp!r}")

        host_b = address.encode("idna")
        if len(host_b) > 255:
            raise OSError("hostname too long for SOCKS5")
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", port)
        writer.write(req)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if hdr[0] != 5 or hdr[1] != 0:
            codes = {
                1: "general failure",
                2: "not allowed",
                3: "network unreachable",
                4: "host unreachable",
                5: "connection refused",
                6: "TTL expired",
                7: "command not supported",
                8: "address type not supported",
            }
            raise OSError(f"SOCKS5 connect failed: {codes.get(hdr[1], hdr[1])}")
        atyp = hdr[3]
        if atyp == 1:
            await reader.readexactly(4 + 2)
        elif atyp == 3:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln + 2)
        elif atyp == 4:
            await reader.readexactly(16 + 2)
        else:
            raise OSError(f"SOCKS5 bad atyp {atyp}")
        return reader, writer
    except Exception:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def socks_health_ok(timeout: float = 12.0) -> bool:
    """True if we can fetch cloudflare trace via local SOCKS (warp=on preferred)."""
    if not _proc_alive():
        return False
    try:
        reader, writer = await open_socks_connection("www.cloudflare.com", 443, timeout=timeout)
        try:
            # Minimal TLS is heavy; just TCP connect through SOCKS is a strong signal.
            # Optional: HTTP on port 80
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        # Second check: HTTP trace via SOCKS to port 80
        reader, writer = await open_socks_connection("www.cloudflare.com", 80, timeout=timeout)
        try:
            writer.write(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")
            await writer.drain()
            data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
            text = data.decode("utf-8", errors="ignore")
            ok = "warp=" in text or "HTTP/1.1 200" in text or "HTTP/1.0 200" in text
            return ok
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"socks health: {e}")
        return False


async def start_warp() -> dict:
    async with _lock:
        try:
            await asyncio.to_thread(_start_proc)
            # brief settle + probe
            await asyncio.sleep(1.5)
            ok = await socks_health_ok()
            _state["socks_ok"] = ok
            if ok:
                _state["last_ok_at"] = time.time()
                _state["fail_streak"] = 0
                _state["last_error"] = ""
            else:
                _state["last_error"] = "wireproxy started but SOCKS health check failed (UDP to Cloudflare may be blocked)"
            _state["enabled"] = True
            return get_status()
        except Exception as e:
            _state["last_error"] = str(e)
            _state["running"] = False
            _state["socks_ok"] = False
            logger.exception("start_warp failed")
            return get_status()


async def stop_warp() -> dict:
    async with _lock:
        _state["enabled"] = False
        await asyncio.to_thread(_stop_proc)
        _state["last_error"] = ""
        return get_status()


async def restart_warp() -> dict:
    async with _lock:
        _state["restarts"] = int(_state.get("restarts") or 0) + 1
        try:
            await asyncio.to_thread(_start_proc)
            await asyncio.sleep(1.5)
            ok = await socks_health_ok()
            _state["socks_ok"] = ok
            _state["enabled"] = True
            if ok:
                _state["last_ok_at"] = time.time()
                _state["fail_streak"] = 0
                _state["last_error"] = ""
            else:
                _state["last_error"] = "restarted but health check failed"
            return get_status()
        except Exception as e:
            _state["last_error"] = str(e)
            _state["running"] = False
            _state["socks_ok"] = False
            return get_status()


async def regenerate_config() -> dict:
    """New WARP registration + rewrite conf, then restart if enabled."""
    async with _lock:
        was_enabled = bool(_state["enabled"])
        await asyncio.to_thread(_stop_proc)
        try:
            await asyncio.to_thread(register_warp_account, True)
            _state["last_error"] = ""
        except Exception as e:
            _state["last_error"] = f"regenerate failed: {e}"
            return get_status()
        if was_enabled:
            try:
                await asyncio.to_thread(_start_proc)
                await asyncio.sleep(1.5)
                ok = await socks_health_ok()
                _state["socks_ok"] = ok
                _state["enabled"] = True
                if ok:
                    _state["last_ok_at"] = time.time()
                    _state["fail_streak"] = 0
            except Exception as e:
                _state["last_error"] = str(e)
                _state["enabled"] = True
        return get_status()


async def set_enabled(enabled: bool) -> dict:
    if enabled:
        return await start_warp()
    return await stop_warp()


async def _health_loop():
    while True:
        try:
            await asyncio.sleep(HEALTH_INTERVAL_S)
            if not _state.get("enabled"):
                continue
            if not _proc_alive():
                _state["running"] = False
                _state["socks_ok"] = False
                _state["fail_streak"] = int(_state.get("fail_streak") or 0) + 1
                _state["last_error"] = "wireproxy process not running"
                if _state["fail_streak"] >= HEALTH_FAIL_THRESHOLD:
                    logger.warning("WARP auto-restart: process dead")
                    await restart_warp()
                continue
            ok = await socks_health_ok()
            if ok:
                _state["socks_ok"] = True
                _state["fail_streak"] = 0
                _state["last_ok_at"] = time.time()
                if not _state.get("last_error") or "health" in str(_state.get("last_error")).lower():
                    _state["last_error"] = ""
            else:
                _state["socks_ok"] = False
                _state["fail_streak"] = int(_state.get("fail_streak") or 0) + 1
                _state["last_error"] = "SOCKS health check failed"
                if _state["fail_streak"] >= HEALTH_FAIL_THRESHOLD:
                    logger.warning("WARP auto-restart: health failures")
                    await restart_warp()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"health loop: {e}")


def ensure_health_task():
    global _health_task
    if _health_task is None or _health_task.done():
        _health_task = asyncio.create_task(_health_loop())


async def bootstrap_from_settings(enabled: bool):
    """Called on app startup after load_db."""
    _state["enabled"] = bool(enabled)
    ensure_health_task()
    if enabled:
        await start_warp()
