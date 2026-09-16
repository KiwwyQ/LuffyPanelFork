# warp_manager.py
# Optional Cloudflare WARP exit via sing-box (userspace WireGuard + local SOCKS5).
# Direct panel traffic never touches this module unless an inbound has use_warp=True.
#
# Design:
# - Non-root, no TUN / NET_ADMIN (sing-box wireguard system: false)
# - Auto-download sing-box, auto-register WARP via Cloudflare client API
# - SOCKS5 CONNECT (TCP) + UDP ASSOCIATE for panel use
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
from typing import Any, Optional, Tuple
from urllib.request import Request, urlopen

logger = logging.getLogger("warp_manager")

WARP_DIR = Path(os.environ.get("WARP_DATA_DIR") or (
    "/data/warp" if os.path.isdir("/data") else str(Path(__file__).resolve().parent / "warp_data")
))
SINGBOX_BIN = WARP_DIR / "sing-box"
WG_CONF = WARP_DIR / "warp-wg.conf"          # human-readable WG keys (register output)
SINGBOX_JSON = WARP_DIR / "sing-box.json"
ACCOUNT_JSON = WARP_DIR / "account.json"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = int(os.environ.get("WARP_SOCKS_PORT", "10808"))
HEALTH_INTERVAL_S = 45
HEALTH_FAIL_THRESHOLD = 3
CF_API = "https://api.cloudflareclient.com/v0a2158"
SINGBOX_RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
WARP_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT_HOST = "engage.cloudflareclient.com"
WARP_ENDPOINT_PORT = 2408

_state: dict[str, Any] = {
    "enabled": False,
    "running": False,
    "socks_ok": False,
    "last_error": "",
    "last_ok_at": 0.0,
    "fail_streak": 0,
    "proc": None,
    "binary_ready": False,
    "config_ready": False,
    "restarts": 0,
    "backend": "sing-box",
}
_lock = asyncio.Lock()
_health_task: Optional[asyncio.Task] = None


def get_status() -> dict:
    return {
        "enabled": bool(_state["enabled"]),
        "running": bool(_state["running"]) and _proc_alive(),
        "socks_ok": bool(_state["socks_ok"]),
        "last_error": str(_state.get("last_error") or ""),
        "binary_ready": bool(_state["binary_ready"]) or SINGBOX_BIN.is_file(),
        "config_ready": bool(_state["config_ready"]) or SINGBOX_JSON.is_file(),
        "socks": f"{SOCKS_HOST}:{SOCKS_PORT}",
        "restarts": int(_state.get("restarts") or 0),
        "last_ok_at": _state.get("last_ok_at") or 0,
        "backend": "sing-box",
    }


def _proc_alive() -> bool:
    p = _state.get("proc")
    return p is not None and p.poll() is None


def _b64_key(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _generate_wg_keypair() -> tuple[str, str]:
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
    try:
        from nacl.bindings import crypto_scalarmult_base
        priv_raw = bytearray(secrets.token_bytes(32))
        priv_raw[0] &= 248
        priv_raw[31] &= 127
        priv_raw[31] |= 64
        priv_raw = bytes(priv_raw)
        pub_raw = crypto_scalarmult_base(priv_raw)
        return _b64_key(priv_raw), _b64_key(pub_raw)
    except Exception as e:
        raise RuntimeError(
            "Need PyNaCl or cryptography for WARP keygen (pip install PyNaCl)"
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


def _write_singbox_config(private_key: str, v4: str, v6: str, peer_pub: str,
                          endpoint_host: str, endpoint_port: int, reserved: list | None = None) -> None:
    """sing-box 1.11+: wireguard as endpoint, socks inbound routes to it."""
    addresses = [f"{v4}/32"]
    if v6:
        addresses.append(f"{v6}/128")
    peer: dict[str, Any] = {
        "address": endpoint_host,
        "port": int(endpoint_port),
        "public_key": peer_pub,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "persistent_keepalive_interval": 25,
    }
    if reserved and len(reserved) == 3:
        peer["reserved"] = reserved

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": SOCKS_HOST,
                "listen_port": SOCKS_PORT,
                "sniff": False,
            }
        ],
        "endpoints": [
            {
                "type": "wireguard",
                "tag": "wg-warp",
                "system": False,
                "mtu": 1280,
                "address": addresses,
                "private_key": private_key,
                "peers": [peer],
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"inbound": ["socks-in"], "outbound": "wg-warp"},
            ],
            "final": "direct",
        },
    }
    SINGBOX_JSON.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    WG_CONF.write_text(
        f"[Interface]\nPrivateKey = {private_key}\nAddress = {', '.join(addresses)}\n"
        f"DNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = {peer_pub}\n"
        f"Endpoint = {endpoint_host}:{endpoint_port}\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n",
        encoding="utf-8",
    )


def register_warp_account(force: bool = False) -> dict:
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    if ACCOUNT_JSON.is_file() and SINGBOX_JSON.is_file() and not force:
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

    try:
        _http_json("PATCH", f"{CF_API}/reg/{device_id}", {"warp_enabled": True}, token=token)
    except Exception as e:
        logger.warning(f"warp_enabled patch: {e}")

    cfg = _http_json("GET", f"{CF_API}/reg/{device_id}", token=token)
    iface = (cfg.get("config") or {}).get("interface") or {}
    peers = (cfg.get("config") or {}).get("peers") or []
    peer = peers[0] if peers else {}
    addresses = iface.get("addresses") or {}
    v4 = addresses.get("v4") or "172.16.0.2"
    v6 = addresses.get("v6") or ""
    peer_pub = peer.get("public_key") or WARP_PEER_PUBLIC_KEY
    endpoint = (peer.get("endpoint") or {}).get("host") or f"{WARP_ENDPOINT_HOST}:{WARP_ENDPOINT_PORT}"
    if ":" in str(endpoint):
        host, _, port_s = endpoint.rpartition(":")
        try:
            eport = int(port_s)
        except ValueError:
            host, eport = WARP_ENDPOINT_HOST, WARP_ENDPOINT_PORT
    else:
        host, eport = str(endpoint), WARP_ENDPOINT_PORT

    reserved = None
    client_id = (cfg.get("config") or {}).get("client_id") or ""
    if client_id:
        try:
            raw = base64.b64decode(client_id + "==")
            if len(raw) >= 3:
                reserved = list(raw[:3])
        except Exception:
            pass

    _write_singbox_config(private_key, v4, v6, peer_pub, host, eport, reserved)
    ACCOUNT_JSON.write_text(json.dumps({
        "id": device_id,
        "account": (result.get("account") or {}),
        "client_id": client_id,
        "endpoint": f"{host}:{eport}",
        "v4": v4,
        "v6": v6,
        "created_at": tos,
    }, indent=2), encoding="utf-8")
    _state["config_ready"] = True
    _state["last_error"] = ""
    logger.info(f"WARP account registered device_id={device_id}")
    return {"ok": True, "reused": False, "device_id": device_id}


def _arch_asset_suffix() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "linux-amd64.tar.gz"
    if machine in ("aarch64", "arm64"):
        return "linux-arm64.tar.gz"
    if machine.startswith("arm"):
        return "linux-armv7.tar.gz"
    return "linux-amd64.tar.gz"


def ensure_singbox_binary() -> Path:
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    if SINGBOX_BIN.is_file() and os.access(SINGBOX_BIN, os.X_OK):
        _state["binary_ready"] = True
        return SINGBOX_BIN

    suffix = _arch_asset_suffix()
    logger.info(f"Downloading sing-box ({suffix})…")
    req = Request(
        SINGBOX_RELEASE_API,
        headers={"User-Agent": "LuffyPanel-WARP/1.0", "Accept": "application/vnd.github+json"},
    )
    with urlopen(req, timeout=60) as resp:
        release = json.loads(resp.read().decode())
    assets = release.get("assets") or []
    url = None
    for a in assets:
        name = a.get("name") or ""
        if name.endswith(suffix) and "sing-box-" in name:
            url = a.get("browser_download_url")
            break
    if not url:
        tag = release.get("tag_name") or "v1.11.0"
        ver = tag.lstrip("v")
        url = (
            f"https://github.com/SagerNet/sing-box/releases/download/{tag}/"
            f"sing-box-{ver}-{suffix}"
        )

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "sing-box.tgz"
        with urlopen(Request(url, headers={"User-Agent": "LuffyPanel-WARP/1.0"}), timeout=180) as r, open(tar_path, "wb") as f:
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
        with tarfile.open(tar_path, "r:gz") as tar:
            member = None
            for m in tar.getmembers():
                if m.isfile() and m.name.split("/")[-1] == "sing-box":
                    member = m
                    break
            if member is None:
                raise RuntimeError("sing-box binary not found in archive")
            tar.extract(member, path=tmp)
            src = Path(tmp) / member.name
        SINGBOX_BIN.write_bytes(src.read_bytes())
        SINGBOX_BIN.chmod(0o755)

    _state["binary_ready"] = True
    logger.info(f"sing-box installed at {SINGBOX_BIN}")
    return SINGBOX_BIN


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
        logger.warning(f"stop sing-box: {e}")
    _state["proc"] = None
    _state["running"] = False
    _state["socks_ok"] = False


def _start_proc() -> None:
    _stop_proc()
    ensure_singbox_binary()
    if not SINGBOX_JSON.is_file():
        register_warp_account(force=False)
    if not SINGBOX_JSON.is_file():
        raise RuntimeError("sing-box config missing after register")
    log_path = WARP_DIR / "sing-box.log"
    log_f = open(log_path, "ab")
    p = subprocess.Popen(
        [str(SINGBOX_BIN), "run", "-c", str(SINGBOX_JSON)],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=str(WARP_DIR),
        start_new_session=True,
    )
    _state["proc"] = p
    _state["running"] = True
    time.sleep(1.5)
    if p.poll() is not None:
        _state["running"] = False
        tail = ""
        try:
            tail = log_path.read_text(encoding="utf-8", errors="ignore")[-1200:]
        except Exception:
            pass
        # Retry with legacy route rule shape if needed
        raise RuntimeError(f"sing-box exited immediately (code={p.returncode}). {tail}")


def _require_warp_up():
    st = get_status()
    if not st.get("enabled"):
        raise OSError("WARP exit requested but WARP process is disabled in Settings")
    if not st.get("running"):
        raise OSError("WARP exit requested but WARP process is not running")


async def open_socks_connection(address: str, port: int, timeout: float = 10.0):
    """SOCKS5 CONNECT via local sing-box (TCP)."""
    _require_warp_up()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(SOCKS_HOST, SOCKS_PORT), timeout=timeout
    )
    try:
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
            raise OSError(f"SOCKS5 CONNECT failed code={hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            await reader.readexactly(6)
        elif atyp == 3:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln + 2)
        elif atyp == 4:
            await reader.readexactly(18)
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


def _socks_udp_header(address: str, port: int, payload: bytes) -> bytes:
    """Build SOCKS5 UDP request header + payload."""
    try:
        socket.inet_pton(socket.AF_INET, address)
        atyp_addr = b"\x01" + socket.inet_aton(address)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            atyp_addr = b"\x04" + socket.inet_pton(socket.AF_INET6, address)
        except OSError:
            host_b = address.encode("idna")
            atyp_addr = b"\x03" + bytes([len(host_b)]) + host_b
    return b"\x00\x00\x00" + atyp_addr + struct.pack("!H", port) + payload


def _parse_socks_udp(data: bytes) -> Tuple[str, int, bytes]:
    if len(data) < 4:
        raise ValueError("short socks udp")
    # RSV RSV FRAG ATYP ...
    pos = 3
    atyp = data[pos]
    pos += 1
    if atyp == 1:
        addr = socket.inet_ntoa(data[pos:pos + 4])
        pos += 4
    elif atyp == 3:
        ln = data[pos]
        pos += 1
        addr = data[pos:pos + ln].decode("utf-8", errors="ignore")
        pos += ln
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, data[pos:pos + 16])
        pos += 16
    else:
        raise ValueError(f"bad atyp {atyp}")
    port = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    return addr, port, data[pos:]


class SocksUdpSession:
    """SOCKS5 UDP ASSOCIATE session bound to one destination."""

    def __init__(self, dest_host: str, dest_port: int):
        self.dest_host = dest_host
        self.dest_port = dest_port
        self._ctrl_reader: Optional[asyncio.StreamReader] = None
        self._ctrl_writer: Optional[asyncio.StreamWriter] = None
        self._udp: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional["_UdpProto"] = None
        self.relay_host = SOCKS_HOST
        self.relay_port = 0

    async def start(self, timeout: float = 10.0):
        _require_warp_up()
        self._ctrl_reader, self._ctrl_writer = await asyncio.wait_for(
            asyncio.open_connection(SOCKS_HOST, SOCKS_PORT), timeout=timeout
        )
        w, r = self._ctrl_writer, self._ctrl_reader
        w.write(b"\x05\x01\x00")
        await w.drain()
        resp = await asyncio.wait_for(r.readexactly(2), timeout=timeout)
        if resp[0] != 5 or resp[1] != 0:
            raise OSError(f"SOCKS5 auth rejected: {resp!r}")
        # ASSOCIATE to 0.0.0.0:0
        w.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        await w.drain()
        hdr = await asyncio.wait_for(r.readexactly(4), timeout=timeout)
        if hdr[0] != 5 or hdr[1] != 0:
            raise OSError(f"SOCKS5 UDP ASSOCIATE failed code={hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            bnd = await r.readexactly(6)
            self.relay_host = socket.inet_ntoa(bnd[:4])
            self.relay_port = int.from_bytes(bnd[4:6], "big")
        elif atyp == 3:
            ln = (await r.readexactly(1))[0]
            host_b = await r.readexactly(ln)
            port_b = await r.readexactly(2)
            self.relay_host = host_b.decode()
            self.relay_port = int.from_bytes(port_b, "big")
        elif atyp == 4:
            bnd = await r.readexactly(18)
            self.relay_host = socket.inet_ntop(socket.AF_INET6, bnd[:16])
            self.relay_port = int.from_bytes(bnd[16:18], "big")
        else:
            raise OSError(f"bad associate atyp {atyp}")
        # Some servers return 0.0.0.0 — use proxy host
        if self.relay_host in ("0.0.0.0", "::", ""):
            self.relay_host = SOCKS_HOST
        loop = asyncio.get_running_loop()
        self._protocol = _UdpProto()
        self._udp, _ = await loop.create_datagram_endpoint(
            lambda: self._protocol, local_addr=("0.0.0.0", 0)
        )

    async def send(self, payload: bytes):
        if not self._udp or not self._protocol:
            raise OSError("UDP session not started")
        pkt = _socks_udp_header(self.dest_host, self.dest_port, payload)
        self._udp.sendto(pkt, (self.relay_host, self.relay_port))

    async def recv(self, timeout: float = 30.0) -> bytes:
        if not self._protocol:
            raise OSError("UDP session not started")
        data = await asyncio.wait_for(self._protocol.queue.get(), timeout=timeout)
        _, _, payload = _parse_socks_udp(data)
        return payload

    async def close(self):
        try:
            if self._udp:
                self._udp.close()
        except Exception:
            pass
        try:
            if self._ctrl_writer:
                self._ctrl_writer.close()
                await self._ctrl_writer.wait_closed()
        except Exception:
            pass


class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()

    def datagram_received(self, data, addr):
        try:
            self.queue.put_nowait(data)
        except Exception:
            pass


async def socks_health_ok(timeout: float = 12.0) -> bool:
    if not _proc_alive():
        return False
    try:
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
            return "warp=" in text or "HTTP/1.1 200" in text or "HTTP/1.0 200" in text
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
            await asyncio.sleep(1.5)
            ok = await socks_health_ok()
            _state["socks_ok"] = ok
            _state["enabled"] = True
            if ok:
                _state["last_ok_at"] = time.time()
                _state["fail_streak"] = 0
                _state["last_error"] = ""
            else:
                _state["last_error"] = (
                    "sing-box started but SOCKS health failed "
                    "(UDP to Cloudflare may be blocked on this host)"
                )
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
    async with _lock:
        was = bool(_state["enabled"])
        await asyncio.to_thread(_stop_proc)
        try:
            await asyncio.to_thread(register_warp_account, True)
            _state["last_error"] = ""
        except Exception as e:
            _state["last_error"] = f"regenerate failed: {e}"
            return get_status()
        if was:
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
                _state["last_error"] = "sing-box process not running"
                if _state["fail_streak"] >= HEALTH_FAIL_THRESHOLD:
                    logger.warning("WARP auto-restart: process dead")
                    await restart_warp()
                continue
            ok = await socks_health_ok()
            if ok:
                _state["socks_ok"] = True
                _state["fail_streak"] = 0
                _state["last_ok_at"] = time.time()
                if "health" in str(_state.get("last_error") or "").lower():
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
    _state["enabled"] = bool(enabled)
    ensure_health_task()
    if enabled:
        await start_warp()
