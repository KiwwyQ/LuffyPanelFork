# exit_proxy_manager.py
# Optional generic exit proxy via sing-box (local SOCKS5 → user-supplied outbound).
# Direct panel traffic never touches this module unless an inbound has use_exit/use_warp=True.
#
# Design:
# - Non-root, no TUN / NET_ADMIN
# - Auto-download sing-box
# - User provides any valid sing-box outbound JSON (VLESS, Trojan, WireGuard, Hysteria, …)
# - SOCKS5 CONNECT (TCP) + UDP ASSOCIATE for panel use
# - Health probe through SOCKS; auto-restart after consecutive failures
# - Fail-closed for exit-enabled inbounds when process is down or config is empty/invalid

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger("exit_proxy_manager")

EXIT_DIR = Path(os.environ.get("EXIT_DATA_DIR") or os.environ.get("WARP_DATA_DIR") or (
    "/data/exit" if os.path.isdir("/data") else str(Path(__file__).resolve().parent / "exit_data")
))
SINGBOX_BIN = EXIT_DIR / "sing-box"
SINGBOX_JSON = EXIT_DIR / "sing-box.json"
USER_CONFIG_PATH = EXIT_DIR / "user_outbound.json"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = int(os.environ.get("EXIT_SOCKS_PORT") or os.environ.get("WARP_SOCKS_PORT", "10808"))
HEALTH_INTERVAL_S = 45
HEALTH_FAIL_THRESHOLD = 3
SINGBOX_RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

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

# Runtime options (persisted by panel via settings)
_options: dict[str, Any] = {
    "config_json": "",       # raw user-supplied outbound JSON string
    "log_level": "warn",
}


def get_status() -> dict:
    return {
        "enabled": bool(_state["enabled"]),
        "running": bool(_state["running"]) and _proc_alive(),
        "socks_ok": bool(_state["socks_ok"]),
        "last_error": str(_state.get("last_error") or ""),
        "binary_ready": bool(_state["binary_ready"]) or SINGBOX_BIN.is_file(),
        "config_ready": bool(_state["config_ready"]) and bool((_options.get("config_json") or "").strip()),
        "socks": f"{SOCKS_HOST}:{SOCKS_PORT}",
        "restarts": int(_state.get("restarts") or 0),
        "last_ok_at": _state.get("last_ok_at") or 0,
        "backend": "sing-box",
        "has_config": bool((_options.get("config_json") or "").strip()),
    }


def get_options() -> dict:
    cfg = str(_options.get("config_json") or "")
    # Do not return the full secret-laden config in every status poll; panel
    # can fetch it explicitly when editing.
    return {
        "log_level": str(_options.get("log_level") or "warn"),
        "config_json": cfg,
        "config_preview": (cfg[:120] + "…") if len(cfg) > 120 else cfg,
        "has_config": bool(cfg.strip()),
    }


def _proc_alive() -> bool:
    p = _state.get("proc")
    return p is not None and p.poll() is None


def set_options_memory(
    config_json: str | None = None,
    log_level: str | None = None,
) -> dict:
    if config_json is not None:
        _options["config_json"] = str(config_json).strip()
    if log_level is not None:
        lvl = str(log_level).strip().lower()
        if lvl not in ("trace", "debug", "info", "warn", "error", "fatal", "panic"):
            lvl = "warn"
        _options["log_level"] = lvl
    return get_options()


def _qs_first(qs: dict, *keys: str, default: str = "") -> str:
    for k in keys:
        vals = qs.get(k) or qs.get(k.lower()) or qs.get(k.upper())
        if vals:
            return unquote(str(vals[0])).strip()
    return default


def _parse_host_port(netloc: str, default_port: int) -> tuple[str, int]:
    """Split host:port, handling [IPv6]:port."""
    netloc = netloc.strip()
    if not netloc:
        raise ValueError("missing host")
    if netloc.startswith("["):
        # [ipv6]:port or [ipv6]
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", netloc)
        if not m:
            raise ValueError(f"bad IPv6 host: {netloc}")
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else default_port
        return host, port
    if netloc.count(":") == 1:
        host, _, port_s = netloc.partition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return host, default_port
    # bare hostname or IPv4, or ambiguous IPv6 without brackets
    return netloc, default_port


def _build_tls_from_params(qs: dict, security: str, sni: str, host_hint: str) -> dict | None:
    """Build sing-box tls block from share-link query params."""
    sec = (security or "").lower()
    if sec in ("", "none", "0"):
        return None

    tls: dict[str, Any] = {"enabled": True}
    server_name = sni or host_hint or ""
    if server_name:
        tls["server_name"] = server_name

    alpn_raw = _qs_first(qs, "alpn")
    if alpn_raw:
        tls["alpn"] = [p.strip() for p in alpn_raw.split(",") if p.strip()]

    fp = _qs_first(qs, "fp", "fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}

    if sec in ("reality", "rl"):
        pbk = _qs_first(qs, "pbk", "publickey", "public_key")
        sid = _qs_first(qs, "sid", "shortid", "short_id")
        spx = _qs_first(qs, "spx", "spiderx")
        if not pbk:
            raise ValueError("REALITY link missing pbk (public key)")
        reality: dict[str, Any] = {"enabled": True, "public_key": pbk}
        if sid:
            reality["short_id"] = sid
        if spx:
            # sing-box may ignore spider_x; keep for compatibility if present
            pass
        tls["reality"] = reality
        if not tls.get("utls"):
            tls["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}

    insecure = _qs_first(qs, "allowInsecure", "allowinsecure", "insecure").lower()
    if insecure in ("1", "true", "yes"):
        tls["insecure"] = True

    return tls


def _build_transport_from_params(qs: dict, net: str) -> dict | None:
    """Build sing-box transport block from share-link type/network params."""
    t = (net or "tcp").lower()
    if t in ("", "tcp", "raw", "none"):
        # Optional HTTP upgrade / header obfuscation still possible, but plain TCP = no transport
        header_type = _qs_first(qs, "headerType", "headertype").lower()
        if header_type == "http":
            path = _qs_first(qs, "path") or "/"
            host = _qs_first(qs, "host")
            tr: dict[str, Any] = {"type": "http", "path": path}
            if host:
                tr["host"] = [host] if not isinstance(host, list) else host
            return tr
        return None

    if t in ("ws", "websocket"):
        path = _qs_first(qs, "path") or "/"
        host = _qs_first(qs, "host")
        tr = {"type": "ws", "path": path}
        if host:
            tr["headers"] = {"Host": host}
        # early data (ed=)
        ed = _qs_first(qs, "ed", "maxEarlyData", "max_early_data")
        if ed:
            try:
                tr["max_early_data"] = int(ed)
                tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
            except ValueError:
                pass
        return tr

    if t in ("httpupgrade", "http_upgrade", "http-upgrade"):
        path = _qs_first(qs, "path") or "/"
        host = _qs_first(qs, "host")
        tr = {"type": "httpupgrade", "path": path}
        if host:
            tr["host"] = host
        return tr

    if t in ("grpc", "gun"):
        service = _qs_first(qs, "serviceName", "servicename", "service_name") or "GunService"
        return {"type": "grpc", "service_name": service}

    if t in ("h2", "http"):
        path = _qs_first(qs, "path") or "/"
        host = _qs_first(qs, "host")
        tr = {"type": "http", "path": path}
        if host:
            tr["host"] = [h.strip() for h in host.split(",")] if isinstance(host, str) else host
        return tr

    if t == "quic":
        return {"type": "quic"}

    if t in ("xhttp", "splithttp"):
        # sing-box 1.10+ xhttp transport
        path = _qs_first(qs, "path") or "/"
        mode = _qs_first(qs, "mode") or "auto"
        host = _qs_first(qs, "host")
        tr = {"type": "http", "path": path}  # fallback; xhttp if available
        # Prefer xhttp when mode is present
        tr = {"type": "xhttp", "path": path, "mode": mode}
        if host:
            tr["host"] = host
        return tr

    # Unknown transport — leave as plain TCP rather than fail hard
    logger.warning("Unknown share-link transport %r — using plain TCP", t)
    return None


def parse_share_link(link: str) -> dict:
    """
    Convert a standard proxy share-link into a sing-box outbound object.

    Supported:
      vless://uuid@host:port?params#name
      trojan://password@host:port?params#name
      ss://method:pass@host:port  (or base64 form)
      vmess://base64  (basic fields)

    Returns a single outbound dict ready for sing-box.
    """
    link = (link or "").strip()
    # Allow accidental surrounding quotes / whitespace
    if (link.startswith('"') and link.endswith('"')) or (link.startswith("'") and link.endswith("'")):
        link = link[1:-1].strip()
    if not link:
        raise ValueError("empty share link")

    # Some clients paste multiple lines — take the first non-empty scheme line
    for line in link.splitlines():
        line = line.strip()
        if "://" in line:
            link = line
            break

    lower = link.lower()
    if lower.startswith("vless://"):
        return _parse_vless_link(link)
    if lower.startswith("trojan://"):
        return _parse_trojan_link(link)
    if lower.startswith("ss://"):
        return _parse_ss_link(link)
    if lower.startswith("vmess://"):
        return _parse_vmess_link(link)

    raise ValueError(
        "unsupported share link (need vless://, trojan://, ss://, or vmess://). "
        "You can still paste a raw sing-box outbound JSON."
    )


def _parse_vless_link(link: str) -> dict:
    # vless://uuid@host:port?query#fragment
    parsed = urlparse(link)
    if parsed.scheme.lower() != "vless":
        raise ValueError("not a vless link")
    uuid = unquote(parsed.username or "")
    if not uuid:
        # Some malformed links put uuid only in path
        raise ValueError("vless link missing uuid")
    host, port = _parse_host_port(parsed.hostname or parsed.netloc.split("@")[-1], 443)
    if parsed.port:
        port = parsed.port
    qs = parse_qs(parsed.query, keep_blank_values=True)

    name = unquote(parsed.fragment) if parsed.fragment else "exit"
    encryption = _qs_first(qs, "encryption") or "none"
    flow = _qs_first(qs, "flow")
    security = _qs_first(qs, "security", "sec") or "none"
    sni = _qs_first(qs, "sni", "serverName", "servername", "peer")
    net = _qs_first(qs, "type", "network", "net") or "tcp"
    packet_encoding = _qs_first(qs, "packetEncoding", "packetencoding", "packet_encoding")

    outbound: dict[str, Any] = {
        "type": "vless",
        "tag": name or "exit",
        "server": host,
        "server_port": int(port),
        "uuid": uuid,
    }
    if flow:
        outbound["flow"] = flow
    if encryption and encryption != "none":
        # sing-box ignores encryption for vless (always none); keep silent
        pass
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    tls = _build_tls_from_params(qs, security, sni, host)
    if tls:
        outbound["tls"] = tls

    transport = _build_transport_from_params(qs, net)
    if transport:
        outbound["transport"] = transport

    return outbound


def _parse_trojan_link(link: str) -> dict:
    parsed = urlparse(link)
    if parsed.scheme.lower() != "trojan":
        raise ValueError("not a trojan link")
    password = unquote(parsed.username or "")
    if not password:
        raise ValueError("trojan link missing password")
    host, port = _parse_host_port(parsed.hostname or "", 443)
    if parsed.port:
        port = parsed.port
    qs = parse_qs(parsed.query, keep_blank_values=True)

    name = unquote(parsed.fragment) if parsed.fragment else "exit"
    security = _qs_first(qs, "security", "sec") or "tls"
    sni = _qs_first(qs, "sni", "peer", "serverName", "servername")
    net = _qs_first(qs, "type", "network", "net") or "tcp"

    outbound: dict[str, Any] = {
        "type": "trojan",
        "tag": name or "exit",
        "server": host,
        "server_port": int(port),
        "password": password,
    }

    tls = _build_tls_from_params(qs, security if security != "none" else "tls", sni, host)
    if tls is None and security != "none":
        # Trojan almost always uses TLS
        tls = {"enabled": True, "server_name": sni or host}
    if tls:
        outbound["tls"] = tls

    transport = _build_transport_from_params(qs, net)
    if transport:
        outbound["transport"] = transport

    return outbound


def _parse_ss_link(link: str) -> dict:
    """
    ss://method:password@host:port#name
    ss://base64(method:password)@host:port#name
    ss://base64(method:password@host:port)#name
    """
    raw = link[5:]  # strip ss://
    name = "exit"
    if "#" in raw:
        raw, _, frag = raw.partition("#")
        name = unquote(frag) or "exit"

    method = password = host = ""
    port = 8388

    def _split_userinfo(userinfo: str) -> tuple[str, str]:
        # method:password — password may contain ':'
        if ":" not in userinfo:
            raise ValueError("ss link missing method:password")
        m, _, p = userinfo.partition(":")
        return unquote(m), unquote(p)

    # SIP002: base64 or plain userinfo @ host:port
    if "@" in raw:
        userinfo, _, hostport = raw.partition("@")
        userinfo = unquote(userinfo)
        # Try base64 decode of userinfo
        try:
            pad = "=" * (-len(userinfo) % 4)
            decoded = base64.urlsafe_b64decode(userinfo + pad).decode("utf-8", errors="strict")
            if ":" in decoded:
                userinfo = decoded
        except Exception:
            pass
        method, password = _split_userinfo(userinfo)
        host, port = _parse_host_port(unquote(hostport), 8388)
    else:
        # Legacy: entire body is base64(method:password@host:port)
        try:
            pad = "=" * (-len(raw) % 4)
            decoded = base64.urlsafe_b64decode(raw + pad).decode("utf-8")
        except Exception as e:
            raise ValueError(f"ss link base64 decode failed: {e}") from e
        if "@" not in decoded:
            raise ValueError("ss link invalid legacy format")
        userinfo, _, hostport = decoded.partition("@")
        method, password = _split_userinfo(userinfo)
        host, port = _parse_host_port(hostport, 8388)

    if not method or not password or not host:
        raise ValueError("ss link incomplete")

    return {
        "type": "shadowsocks",
        "tag": name or "exit",
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


def _parse_vmess_link(link: str) -> dict:
    """Basic vmess://base64(json) support."""
    raw = link[8:]  # strip vmess://
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    try:
        pad = "=" * (-len(raw) % 4)
        data = json.loads(base64.urlsafe_b64decode(raw + pad).decode("utf-8"))
    except Exception as e:
        raise ValueError(f"vmess link decode failed: {e}") from e

    host = data.get("add") or data.get("host") or ""
    port = int(data.get("port") or 443)
    uuid = data.get("id") or ""
    name = data.get("ps") or data.get("remark") or "exit"
    aid = data.get("aid") or data.get("alterId") or 0
    net = (data.get("net") or "tcp").lower()
    tls_flag = (data.get("tls") or "").lower()
    sni = data.get("sni") or data.get("host") or host
    path = data.get("path") or "/"
    host_header = data.get("host") or ""

    if not host or not uuid:
        raise ValueError("vmess link missing address or id")

    outbound: dict[str, Any] = {
        "type": "vmess",
        "tag": str(name) or "exit",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": data.get("scy") or data.get("security") or "auto",
        "alter_id": int(aid) if aid else 0,
    }

    if tls_flag in ("tls", "reality"):
        tls: dict[str, Any] = {"enabled": True, "server_name": sni or host}
        fp = data.get("fp") or ""
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        outbound["tls"] = tls

    # Transport
    if net in ("ws", "websocket"):
        tr: dict[str, Any] = {"type": "ws", "path": path or "/"}
        if host_header:
            tr["headers"] = {"Host": host_header}
        outbound["transport"] = tr
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": data.get("path") or data.get("serviceName") or "GunService",
        }
    elif net in ("h2", "http"):
        tr = {"type": "http", "path": path or "/"}
        if host_header:
            tr["host"] = [host_header]
        outbound["transport"] = tr

    return outbound


def _looks_like_share_link(text: str) -> bool:
    t = text.strip().lower()
    return (
        t.startswith("vless://")
        or t.startswith("trojan://")
        or t.startswith("ss://")
        or t.startswith("vmess://")
        or any(
            line.strip().lower().startswith(p)
            for line in t.splitlines()
            for p in ("vless://", "trojan://", "ss://", "vmess://")
        )
    )


def _normalize_user_outbound(raw: Any) -> list[dict]:
    """
    Accept several convenient shapes and always return a list of outbound dicts.
    Supported:
      - share links: vless://, trojan://, ss://, vmess://
      - single outbound object:  {"type":"vless", ...}
      - list of outbounds:       [{"type":"vless", ...}, ...]
      - full-ish config with "outbounds" key
      - object that already has "type" (treated as one outbound)
    """
    if raw is None:
        raise ValueError("empty config")
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            raise ValueError("empty config string")
        # Share-link path
        if _looks_like_share_link(raw):
            try:
                ob = parse_share_link(raw)
                return _normalize_user_outbound(ob)
            except ValueError:
                raise
            except Exception as e:
                raise ValueError(f"share link parse failed: {e}") from e
        # JSON path
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            # Maybe user pasted a share link without scheme detection edge-case
            if "://" in raw:
                raise ValueError(
                    f"not valid JSON and share-link parse failed earlier; "
                    f"JSON error: {e}"
                ) from e
            raise ValueError(f"invalid JSON: {e}") from e

    if not isinstance(raw, (dict, list)):
        raise ValueError("config must be a JSON object/array or a share link")

    if isinstance(raw, list):
        outbounds = raw
    elif "outbounds" in raw and isinstance(raw["outbounds"], list):
        outbounds = raw["outbounds"]
    elif "type" in raw:
        outbounds = [raw]
    else:
        raise ValueError(
            "config must be a share link (vless://, trojan://, …), "
            "a sing-box outbound object, a list of outbounds, "
            "or an object containing an 'outbounds' array"
        )

    cleaned: list[dict] = []
    for i, ob in enumerate(outbounds):
        if not isinstance(ob, dict):
            raise ValueError(f"outbound[{i}] is not an object")
        if not ob.get("type"):
            raise ValueError(f"outbound[{i}] missing 'type'")
        # Skip pure direct/block/dns outbounds from user list — we add our own direct.
        t = str(ob.get("type") or "").lower()
        if t in ("direct", "block", "dns", "selector", "urltest", "uri"):
            continue
        if not ob.get("tag"):
            ob = dict(ob)
            ob["tag"] = f"exit-{i}" if i else "exit"
        cleaned.append(ob)

    if not cleaned:
        raise ValueError("no usable outbound found (need at least one non-direct outbound)")
    return cleaned


def _build_singbox_config(outbounds: list[dict], log_level: str = "warn") -> dict:
    """Wrap user outbounds into a minimal sing-box config with local SOCKS inbound."""
    primary_tag = outbounds[0].get("tag") or "exit"
    all_outbounds = list(outbounds) + [{"type": "direct", "tag": "direct"}]

    return {
        "log": {
            "level": log_level or "warn",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": SOCKS_HOST,
                "listen_port": SOCKS_PORT,
                "sniff": False,
            }
        ],
        "outbounds": all_outbounds,
        "route": {
            "rules": [
                {"inbound": ["socks-in"], "outbound": primary_tag},
            ],
            "final": "direct",
        },
    }


def write_config_from_user(config_json: str | None = None, log_level: str | None = None) -> dict:
    """
    Parse user outbound JSON, write sing-box.json, mark config_ready.
    Does NOT start/stop the process.
    """
    if config_json is not None:
        set_options_memory(config_json=config_json)
    if log_level is not None:
        set_options_memory(log_level=log_level)

    raw = _options.get("config_json") or ""
    if not str(raw).strip():
        _state["config_ready"] = False
        if SINGBOX_JSON.is_file():
            try:
                SINGBOX_JSON.unlink()
            except Exception:
                pass
        raise ValueError("Exit Proxy config is empty — paste a sing-box outbound JSON first")

    outbounds = _normalize_user_outbound(raw)
    cfg = _build_singbox_config(outbounds, log_level=str(_options.get("log_level") or "warn"))

    EXIT_DIR.mkdir(parents=True, exist_ok=True)
    SINGBOX_JSON.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    USER_CONFIG_PATH.write_text(
        json.dumps(outbounds, indent=2) if len(outbounds) > 1 else json.dumps(outbounds[0], indent=2),
        encoding="utf-8",
    )
    _state["config_ready"] = True
    _state["last_error"] = ""
    logger.info("Exit Proxy config written (%d outbound(s), primary=%s)",
                len(outbounds), outbounds[0].get("tag"))
    return get_options()


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
    EXIT_DIR.mkdir(parents=True, exist_ok=True)
    if SINGBOX_BIN.is_file() and os.access(SINGBOX_BIN, os.X_OK):
        _state["binary_ready"] = True
        return SINGBOX_BIN

    suffix = _arch_asset_suffix()
    logger.info("Downloading sing-box (%s)…", suffix)
    req = Request(
        SINGBOX_RELEASE_API,
        headers={"User-Agent": "LuffyPanel-Exit/1.0", "Accept": "application/vnd.github+json"},
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
        with urlopen(Request(url, headers={"User-Agent": "LuffyPanel-Exit/1.0"}), timeout=180) as r, open(tar_path, "wb") as f:
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
    logger.info("sing-box installed at %s", SINGBOX_BIN)
    return SINGBOX_BIN


def _stop_proc() -> None:
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
        logger.warning("stop sing-box: %s", e)
    _state["proc"] = None
    _state["running"] = False
    _state["socks_ok"] = False


def _start_proc() -> None:
    _stop_proc()
    ensure_singbox_binary()

    # Ensure config file exists from current options
    if not SINGBOX_JSON.is_file() or not (_options.get("config_json") or "").strip():
        if (_options.get("config_json") or "").strip():
            write_config_from_user()
        else:
            raise RuntimeError("Exit Proxy config is empty — paste a sing-box outbound JSON in Settings")

    if not SINGBOX_JSON.is_file():
        raise RuntimeError("sing-box config missing after write")

    log_path = EXIT_DIR / "sing-box.log"
    log_f = open(log_path, "ab")
    p = subprocess.Popen(
        [str(SINGBOX_BIN), "run", "-c", str(SINGBOX_JSON)],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=str(EXIT_DIR),
        start_new_session=True,
    )
    _state["proc"] = p
    _state["running"] = True
    time.sleep(1.5)
    if p.poll() is not None:
        _state["running"] = False
        tail = ""
        try:
            tail = log_path.read_text(encoding="utf-8", errors="ignore")[-1500:]
        except Exception:
            pass
        raise RuntimeError(f"sing-box exited immediately (code={p.returncode}). {tail}")


def _require_exit_up() -> None:
    st = get_status()
    if not st.get("enabled"):
        raise OSError("Exit Proxy requested but process is disabled in Settings")
    if not st.get("running"):
        raise OSError("Exit Proxy requested but process is not running")
    if not st.get("config_ready") and not st.get("has_config"):
        raise OSError("Exit Proxy requested but no outbound config is set")


async def open_socks_connection(address: str, port: int, timeout: float = 10.0):
    """SOCKS5 CONNECT via local sing-box (TCP)."""
    _require_exit_up()
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
        _require_exit_up()
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
    """TCP health check through the local SOCKS (does not require the exit to be Cloudflare)."""
    if not _proc_alive():
        return False
    try:
        reader, writer = await open_socks_connection("1.1.1.1", 80, timeout=timeout)
        try:
            writer.write(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n")
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
            return (
                "HTTP/1.1 200" in text
                or "HTTP/1.0 200" in text
                or "HTTP/1.1 301" in text
                or "HTTP/1.1 302" in text
                or "cloudflare" in text.lower()
                or len(data) > 20
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as e:
        logger.debug("socks health: %s", e)
        return False


async def start_exit() -> dict:
    async with _lock:
        try:
            if not (_options.get("config_json") or "").strip():
                _state["last_error"] = "No outbound config set — paste a sing-box outbound JSON in Settings"
                _state["enabled"] = True
                _state["running"] = False
                _state["socks_ok"] = False
                return get_status()
            await asyncio.to_thread(write_config_from_user)
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
                    "(outbound may be unreachable or blocked from this host)"
                )
            return get_status()
        except Exception as e:
            _state["last_error"] = str(e)
            _state["running"] = False
            _state["socks_ok"] = False
            _state["enabled"] = True
            logger.exception("start_exit failed")
            return get_status()


async def stop_exit() -> dict:
    async with _lock:
        _state["enabled"] = False
        await asyncio.to_thread(_stop_proc)
        _state["last_error"] = ""
        return get_status()


async def restart_exit() -> dict:
    async with _lock:
        _state["restarts"] = int(_state.get("restarts") or 0) + 1
        try:
            if not (_options.get("config_json") or "").strip():
                _state["last_error"] = "No outbound config set"
                _state["running"] = False
                _state["socks_ok"] = False
                return get_status()
            await asyncio.to_thread(write_config_from_user)
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


async def set_enabled(enabled: bool) -> dict:
    if enabled:
        return await start_exit()
    return await stop_exit()


async def apply_config(
    config_json: str | None = None,
    log_level: str | None = None,
    restart: bool = True,
) -> dict:
    """Update config / log level, rewrite sing-box.json, optionally restart if enabled."""
    async with _lock:
        was = bool(_state.get("enabled")) and _proc_alive()
        try:
            if config_json is not None or log_level is not None:
                await asyncio.to_thread(write_config_from_user, config_json, log_level)
            _state["last_error"] = ""
        except Exception as e:
            _state["last_error"] = f"config: {e}"
            return {**get_status(), **get_options()}
        if restart and (was or _state.get("enabled")):
            try:
                await asyncio.to_thread(_start_proc)
                await asyncio.sleep(1.5)
                ok = await socks_health_ok()
                _state["socks_ok"] = ok
                _state["enabled"] = True
                _state["restarts"] = int(_state.get("restarts") or 0) + 1
                if ok:
                    _state["last_ok_at"] = time.time()
                    _state["fail_streak"] = 0
                else:
                    _state["last_error"] = "config applied; health check failed"
            except Exception as e:
                _state["last_error"] = str(e)
                _state["running"] = False
        return {**get_status(), **get_options()}


async def _health_loop():
    while True:
        try:
            await asyncio.sleep(HEALTH_INTERVAL_S)
            if not _state.get("enabled"):
                continue
            if not (_options.get("config_json") or "").strip():
                _state["running"] = False
                _state["socks_ok"] = False
                continue
            if not _proc_alive():
                _state["running"] = False
                _state["socks_ok"] = False
                _state["fail_streak"] = int(_state.get("fail_streak") or 0) + 1
                _state["last_error"] = "sing-box process not running"
                if _state["fail_streak"] >= HEALTH_FAIL_THRESHOLD:
                    logger.warning("Exit Proxy auto-restart: process dead")
                    await restart_exit()
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
                    logger.warning("Exit Proxy auto-restart: health failures")
                    await restart_exit()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug("health loop: %s", e)


def ensure_health_task():
    global _health_task
    if _health_task is None or _health_task.done():
        _health_task = asyncio.create_task(_health_loop())


async def bootstrap_from_settings(enabled: bool, config_json: str = "", log_level: str = "warn"):
    set_options_memory(config_json=config_json or "", log_level=log_level or "warn")
    _state["enabled"] = bool(enabled)
    ensure_health_task()
    if enabled and (config_json or "").strip():
        await start_exit()
    elif enabled and not (config_json or "").strip():
        _state["last_error"] = "Exit Proxy enabled but no outbound config is set"
        logger.warning(_state["last_error"])


# ---------------------------------------------------------------------------
# Backward-compatible aliases so any leftover "warp_*" calls still work during
# the transition. Prefer the exit_* names in new code.
# ---------------------------------------------------------------------------
start_warp = start_exit
stop_warp = stop_exit
restart_warp = restart_exit
regenerate_config = restart_exit  # no longer regenerates keys; just restarts
