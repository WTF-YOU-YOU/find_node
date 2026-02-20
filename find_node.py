#!/usr/bin/env python3
"""
find_node - Auto-collect free public proxy nodes and generate Clash Meta config.
"""

import base64
import json
import re
import urllib.parse
import datetime
import sys
import time
import socket
import ssl
import concurrent.futures
import yaml
import requests

import random

# ============================================================
# Subscription sources (public free proxy aggregators)
# ============================================================
SUB_URLS = [
    # --- Popular GitHub aggregators ---
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/v2",
    # --- New sources (verified 2026-02-20) ---
    # ebrasha: updated every 15 min, all protocols
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
    # Epodonios: updated every 5 min, vmess/vless/trojan/ss
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    # mahdibland: aggregator with speed-tested nodes
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    # Mahdi0024: auto-collected and tested proxies
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    # snakem982: proxypool (Clash Meta YAML format)
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
]

REQUEST_TIMEOUT = 15
MAX_NODES = 500  # Max nodes to include in final config
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
}

# ============================================================
# URI Parsers
# ============================================================

def safe_b64decode(s: str) -> str:
    """Base64 decode with padding fix."""
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.b64decode(s).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def parse_vmess(uri: str) -> dict | None:
    """Parse vmess:// URI to Clash proxy dict."""
    try:
        raw = uri.replace("vmess://", "")
        decoded = safe_b64decode(raw)
        if not decoded:
            return None
        cfg = json.loads(decoded)

        name = cfg.get("ps") or cfg.get("remark") or f"vmess-{cfg.get('add', 'unknown')}"
        port = int(cfg.get("port", 0))
        if port <= 0 or port > 65535:
            return None

        proxy = {
            "name": name,
            "type": "vmess",
            "server": cfg.get("add", ""),
            "port": port,
            "uuid": cfg.get("id", ""),
            "alterId": int(cfg.get("aid", 0)),
            "cipher": cfg.get("scy", "auto"),
            "tls": cfg.get("tls", "") == "tls",
            "skip-cert-verify": True,
            "network": cfg.get("net", "tcp"),
        }

        if not proxy["server"] or not proxy["uuid"]:
            return None

        # WebSocket options
        if proxy["network"] == "ws":
            ws_opts = {}
            path = cfg.get("path", "/")
            if path:
                ws_opts["path"] = path
            host = cfg.get("host", "")
            if host:
                ws_opts["headers"] = {"Host": host}
            if ws_opts:
                proxy["ws-opts"] = ws_opts

        # gRPC options
        if proxy["network"] == "grpc":
            sn = cfg.get("path", "")
            if sn:
                proxy["grpc-opts"] = {"grpc-service-name": sn}

        # h2 options
        if proxy["network"] == "h2":
            h2_opts = {}
            path = cfg.get("path", "/")
            if path:
                h2_opts["path"] = path
            host = cfg.get("host", "")
            if host:
                h2_opts["host"] = [host]
            if h2_opts:
                proxy["h2-opts"] = h2_opts

        # SNI / servername
        sni = cfg.get("sni") or cfg.get("host", "")
        if sni and proxy["tls"]:
            proxy["servername"] = sni

        return proxy
    except Exception:
        return None


def parse_vless(uri: str) -> dict | None:
    """Parse vless:// URI to Clash proxy dict."""
    try:
        raw = uri.replace("vless://", "")
        if "@" not in raw:
            return None

        uuid_part, rest = raw.split("@", 1)
        uuid = uuid_part.strip()

        # Split fragment (name)
        name = ""
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
            name = urllib.parse.unquote(fragment).strip()

        # Split query
        params = {}
        if "?" in rest:
            addr_part, query_str = rest.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query_str))
        else:
            addr_part = rest

        # Parse host:port
        if ":" not in addr_part:
            return None
        host, port_str = addr_part.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_str)
        if port <= 0 or port > 65535:
            return None

        if not name:
            name = f"vless-{host}"

        proxy = {
            "name": name,
            "type": "vless",
            "server": host,
            "port": port,
            "uuid": uuid,
            "tls": params.get("security", "") in ("tls", "reality"),
            "network": params.get("type", "tcp"),
            "udp": True,
        }

        # Flow
        flow = params.get("flow", "")
        if flow:
            proxy["flow"] = flow

        # Encryption
        proxy["encryption"] = params.get("encryption", "none")

        # SNI
        sni = params.get("sni", "") or params.get("serverName", "")
        if sni:
            proxy["servername"] = sni

        # Client fingerprint
        fp = params.get("fp", "")
        if fp:
            proxy["client-fingerprint"] = fp

        # Reality options
        if params.get("security") == "reality":
            proxy["tls"] = True
            pbk = params.get("pbk", "")
            sid = params.get("sid", "")
            if pbk:
                reality_opts = {"public-key": pbk}
                if sid:
                    reality_opts["short-id"] = sid
                proxy["reality-opts"] = reality_opts
            proxy["skip-cert-verify"] = False

        # WebSocket
        if proxy["network"] == "ws":
            ws_opts = {}
            path = params.get("path", "/")
            if path:
                ws_opts["path"] = urllib.parse.unquote(path)
            ws_host = params.get("host", "")
            if ws_host:
                ws_opts["headers"] = {"Host": ws_host}
            if ws_opts:
                proxy["ws-opts"] = ws_opts

        # gRPC
        if proxy["network"] == "grpc":
            sn = params.get("serviceName", "")
            if sn:
                proxy["grpc-opts"] = {"grpc-service-name": sn}

        return proxy
    except Exception:
        return None


def parse_ss(uri: str) -> dict | None:
    """Parse ss:// URI to Clash proxy dict."""
    try:
        raw = uri.replace("ss://", "")

        # Extract name fragment
        name = ""
        if "#" in raw:
            raw, fragment = raw.rsplit("#", 1)
            name = urllib.parse.unquote(fragment).strip()

        # Two formats:
        # 1) base64(method:password)@host:port
        # 2) base64(method:password@host:port)
        if "@" in raw:
            user_info, server_part = raw.rsplit("@", 1)
            decoded = safe_b64decode(user_info)
            if not decoded or ":" not in decoded:
                # Try URL-decode
                decoded = urllib.parse.unquote(user_info)
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)

            if ":" not in server_part:
                return None
            host, port_str = server_part.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_str.split("/")[0].split("?")[0])
        else:
            decoded = safe_b64decode(raw)
            if not decoded:
                return None
            # method:password@host:port
            if "@" not in decoded:
                return None
            user_info, server_part = decoded.rsplit("@", 1)
            method, password = user_info.split(":", 1)
            host, port_str = server_part.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_str)

        if port <= 0 or port > 65535 or not host:
            return None

        if not name:
            name = f"ss-{host}:{port}"

        proxy = {
            "name": name,
            "type": "ss",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
        }
        return proxy
    except Exception:
        return None


def parse_ssr(uri: str) -> dict | None:
    """Parse ssr:// URI to Clash proxy dict."""
    try:
        raw = uri.replace("ssr://", "")
        decoded = safe_b64decode(raw)
        if not decoded:
            return None

        # host:port:protocol:method:obfs:base64pass/?params
        main_part = decoded.split("/?")[0] if "/?" in decoded else decoded
        parts = main_part.split(":")
        if len(parts) < 6:
            return None

        host = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_b64 = parts[5]
        password = safe_b64decode(password_b64)

        if port <= 0 or port > 65535 or not host:
            return None

        # Parse optional params
        name = f"ssr-{host}:{port}"
        if "/?" in decoded:
            param_str = decoded.split("/?")[1]
            params = dict(urllib.parse.parse_qsl(param_str))
            remarks = params.get("remarks", "")
            if remarks:
                name = safe_b64decode(remarks) or name

        proxy = {
            "name": name,
            "type": "ssr",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
            "protocol": protocol,
            "obfs": obfs,
        }
        return proxy
    except Exception:
        return None


def parse_trojan(uri: str) -> dict | None:
    """Parse trojan:// URI to Clash proxy dict."""
    try:
        raw = uri.replace("trojan://", "")

        # Extract name fragment
        name = ""
        if "#" in raw:
            raw, fragment = raw.rsplit("#", 1)
            name = urllib.parse.unquote(fragment).strip()

        if "@" not in raw:
            return None

        password, rest = raw.split("@", 1)
        password = urllib.parse.unquote(password)

        # Parse query params
        params = {}
        if "?" in rest:
            addr_part, query_str = rest.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query_str))
        else:
            addr_part = rest

        if ":" not in addr_part:
            return None
        host, port_str = addr_part.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_str.split("/")[0])

        if port <= 0 or port > 65535 or not host:
            return None

        if not name:
            name = f"trojan-{host}:{port}"

        sni = params.get("sni", "") or params.get("peer", "") or host

        proxy = {
            "name": name,
            "type": "trojan",
            "server": host,
            "port": port,
            "password": password,
            "sni": sni,
            "skip-cert-verify": True,
            "udp": True,
        }

        # WebSocket
        net_type = params.get("type", "tcp")
        if net_type == "ws":
            proxy["network"] = "ws"
            ws_opts = {}
            path = params.get("path", "")
            if path:
                ws_opts["path"] = urllib.parse.unquote(path)
            ws_host = params.get("host", "")
            if ws_host:
                ws_opts["headers"] = {"Host": ws_host}
            if ws_opts:
                proxy["ws-opts"] = ws_opts

        # gRPC
        if net_type == "grpc":
            proxy["network"] = "grpc"
            sn = params.get("serviceName", "")
            if sn:
                proxy["grpc-opts"] = {"grpc-service-name": sn}

        return proxy
    except Exception:
        return None


def parse_hysteria2(uri: str) -> dict | None:
    """Parse hysteria2:// or hy2:// URI to Clash proxy dict."""
    try:
        raw = uri
        for prefix in ("hysteria2://", "hy2://"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break

        name = ""
        if "#" in raw:
            raw, fragment = raw.rsplit("#", 1)
            name = urllib.parse.unquote(fragment).strip()

        if "@" not in raw:
            return None

        password, rest = raw.split("@", 1)

        params = {}
        if "?" in rest:
            addr_part, query_str = rest.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query_str))
        else:
            addr_part = rest

        if ":" not in addr_part:
            return None
        host, port_str = addr_part.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_str.split("/")[0])

        if port <= 0 or port > 65535 or not host:
            return None
        if not name:
            name = f"hy2-{host}:{port}"

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": host,
            "port": port,
            "password": password,
            "skip-cert-verify": True,
        }

        sni = params.get("sni", "")
        if sni:
            proxy["sni"] = sni

        obfs = params.get("obfs", "")
        if obfs:
            proxy["obfs"] = obfs
            obfs_pw = params.get("obfs-password", "")
            if obfs_pw:
                proxy["obfs-password"] = obfs_pw

        return proxy
    except Exception:
        return None


# ============================================================
# Fetch & Parse
# ============================================================

def parse_clash_yaml(text: str) -> list[dict]:
    """Parse Clash YAML content and extract proxies."""
    proxies = []
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            raw_proxies = data.get("proxies", [])
            if isinstance(raw_proxies, list):
                for p in raw_proxies:
                    if isinstance(p, dict) and "name" in p and "server" in p:
                        proxies.append(p)
    except Exception:
        pass
    return proxies


def parse_uri_line(line: str) -> dict | None:
    """Parse a single proxy URI line."""
    line = line.strip()
    if not line:
        return None

    if line.startswith("vmess://"):
        return parse_vmess(line)
    elif line.startswith("vless://"):
        return parse_vless(line)
    elif line.startswith("ss://"):
        return parse_ss(line)
    elif line.startswith("ssr://"):
        return parse_ssr(line)
    elif line.startswith("trojan://"):
        return parse_trojan(line)
    elif line.startswith("hysteria2://") or line.startswith("hy2://"):
        return parse_hysteria2(line)
    return None


def fetch_and_parse(url: str) -> list[dict]:
    """Fetch a subscription URL and return list of proxy dicts."""
    proxies = []
    try:
        print(f"  Fetching: {url}")
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        text = resp.text.strip()
    except Exception as e:
        print(f"  [FAIL] {url}: {e}")
        return []

    # Try to decode as base64 first
    decoded = safe_b64decode(text)
    if decoded and any(
        decoded.startswith(p) for p in ("vmess://", "vless://", "ss://", "ssr://", "trojan://", "hysteria2://", "hy2://")
    ):
        text = decoded

    # Check if it's a Clash YAML config
    if text.lstrip().startswith(("proxies:", "port:", "mixed-port:", "allow-lan:")):
        return parse_clash_yaml(text)

    # Parse as URI list
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        proxy = parse_uri_line(line)
        if proxy:
            proxies.append(proxy)

    print(f"  [OK] {url}: {len(proxies)} nodes")
    return proxies


# ============================================================
# Dedup & Categorize
# ============================================================

# Known valid SS/SSR ciphers
VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "rc4",
    "chacha20", "chacha20-ietf", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none", "plain",
}


def validate_proxy(p: dict) -> bool:
    """Validate that a proxy has all required fields with sane values."""
    ptype = p.get("type", "")
    server = p.get("server", "")
    port = p.get("port", 0)

    # Basic checks
    if not server or not ptype:
        return False
    if not isinstance(port, int) or port <= 0 or port > 65535:
        return False
    # Reject loopback/private
    if server.startswith(("127.", "10.", "192.168.", "0.0.0.", "localhost")):
        return False

    if ptype == "vmess":
        if not p.get("uuid"):
            return False
    elif ptype == "vless":
        if not p.get("uuid"):
            return False
    elif ptype == "ss":
        cipher = p.get("cipher", "")
        password = p.get("password", "")
        if not cipher or not password:
            return False
        if cipher.lower() not in VALID_SS_CIPHERS:
            return False
        # 2022-blake3-* ciphers require valid base64-encoded keys
        if cipher.lower().startswith("2022-blake3-"):
            try:
                key_bytes = base64.b64decode(password)
                # aes-128 needs 16-byte key, aes-256/chacha20 need 32-byte key
                if "128" in cipher and len(key_bytes) != 16:
                    return False
                if ("256" in cipher or "chacha20" in cipher) and len(key_bytes) != 32:
                    return False
            except Exception:
                return False
    elif ptype == "ssr":
        if not p.get("cipher") or not p.get("password"):
            return False
        if not p.get("protocol") or not p.get("obfs"):
            return False
    elif ptype == "trojan":
        if not p.get("password"):
            return False
    elif ptype == "hysteria2":
        if not p.get("password"):
            return False
    elif ptype in ("socks5", "http"):
        pass  # minimal requirements
    else:
        return False  # unknown type

    return True


def clean_proxy(p: dict) -> dict:
    """Clean up a proxy dict: remove empty fields, set defaults."""
    cleaned = {}
    for k, v in p.items():
        # Remove None and empty string values (except password which can look empty-ish)
        if v is None:
            continue
        if isinstance(v, str) and v == "" and k != "password":
            continue
        # Remove empty dict values
        if isinstance(v, dict) and not v:
            continue
        cleaned[k] = v

    # Set default network for vmess if missing
    if cleaned.get("type") == "vmess" and "network" not in cleaned:
        cleaned["network"] = "tcp"

    # Set default cipher for vmess if missing
    if cleaned.get("type") == "vmess" and not cleaned.get("cipher"):
        cleaned["cipher"] = "auto"

    return cleaned


def dedup_proxies(proxies: list[dict]) -> list[dict]:
    """Deduplicate proxies by server+port+type, keep unique names."""
    seen = set()
    name_count = {}
    result = []

    for p in proxies:
        key = (p.get("server", ""), p.get("port", 0), p.get("type", ""))
        if key in seen:
            continue
        seen.add(key)

        # Ensure unique name
        orig_name = p["name"]
        if orig_name in name_count:
            name_count[orig_name] += 1
            p["name"] = f"{orig_name} #{name_count[orig_name]}"
        else:
            name_count[orig_name] = 1

        result.append(p)

    return result


REGION_KEYWORDS = {
    "JP": (["日本", "JP", "Japan", "东京", "Tokyo", "大阪", "Osaka"], "🇯🇵 日本"),
    "US": (["美国", "US", "USA", "United States", "洛杉矶", "Los Angeles", "San Jose",
             "Ashburn", "Seattle", "New York", "纽约", "紐約", "圣何塞", "聖荷西", "Dallas"], "🇺🇸 美国"),
    "SG": (["新加坡", "SG", "Singapore"], "🇸🇬 新加坡"),
    "KR": (["韩国", "KR", "Korea", "首尔", "Seoul"], "🇰🇷 韩国"),
    "GB": (["英国", "GB", "UK", "United Kingdom", "London", "伦敦"], "🇬🇧 英国"),
    "DE": (["德国", "DE", "Germany", "Frankfurt", "法兰克福"], "🇩🇪 德国"),
    "FR": (["法国", "FR", "France", "Paris", "巴黎"], "🇫🇷 法国"),
    "RU": (["俄罗斯", "RU", "Russia", "Moscow", "莫斯科"], "🇷🇺 俄罗斯"),
    "CA": (["加拿大", "CA", "Canada", "Toronto", "Montreal"], "🇨🇦 加拿大"),
    "AU": (["澳大利亚", "AU", "Australia", "Sydney", "悉尼"], "🇦🇺 澳大利亚"),
    "IN": (["印度", "IN", "India", "Mumbai", "孟买"], "🇮🇳 印度"),
    "BR": (["巴西", "BR", "Brazil", "圣保罗", "Sao Paulo"], "🇧🇷 巴西"),
}

# China/HK/TW and high-risk keywords to EXCLUDE
EXCLUDED_KEYWORDS = [
    "香港", "HK", "Hong Kong", "台湾", "TW", "Taiwan", "台北",
    "中国", "CN", "China", "北京", "上海", "广州", "深圳",
    "内蒙", "回国", "剩余", "过期", "到期", "官网", "流量",
    "高风险", "黑名单", "禁止", "封禁", "blocked",
    "127.0.0.1", "localhost",
]

# Regions considered "premium" (Europe & Americas) - get priority in selection
PRIORITY_REGIONS = {"🇺🇸 美国", "🇬🇧 英国", "🇩🇪 德国", "🇫🇷 法国", "🇨🇦 加拿大", "🇦🇺 澳大利亚"}


def classify_region(proxy_name: str) -> list[str]:
    """Return list of region group names this proxy belongs to."""
    regions = []
    for _code, (keywords, group_name) in REGION_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in proxy_name.lower():
                regions.append(group_name)
                break
    return regions


def is_excluded(proxy: dict) -> bool:
    """Check if a proxy should be excluded (China/HK/TW/invalid)."""
    name = proxy.get("name", "").lower()
    server = proxy.get("server", "").lower()

    for kw in EXCLUDED_KEYWORDS:
        if kw.lower() in name or kw.lower() in server:
            return True

    # Exclude loopback / private IPs
    if server.startswith(("127.", "10.", "192.168.", "0.0.0.")):
        return True

    return False


# ============================================================
# Latency Testing
# ============================================================

TCP_TIMEOUT = 3  # seconds per connection test
MAX_WORKERS = 80  # concurrent test threads
MAX_DELAY_MS = 2000  # discard nodes with latency above this

# Reusable SSL context (skip cert verify for speed)
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def test_tcp_latency(proxy: dict) -> int | None:
    """Test latency: DNS + TCP + TLS handshake (if TLS). Returns ms or None."""
    server = proxy.get("server", "")
    port = proxy.get("port", 0)
    use_tls = proxy.get("tls", False)
    if not server or not port:
        return None

    sock = None
    try:
        start = time.perf_counter()

        # DNS resolve
        addr_info = socket.getaddrinfo(server, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return None
        family, socktype, proto, _, sockaddr = addr_info[0]

        # TCP connect
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(TCP_TIMEOUT)
        sock.connect(sockaddr)

        # TLS handshake for TLS-enabled nodes (measures real proxy path latency)
        if use_tls or port == 443:
            sni = proxy.get("servername") or proxy.get("sni") or server
            ssock = _SSL_CTX.wrap_socket(sock, server_hostname=sni)
            ssock.do_handshake()
            ssock.close()
            sock = None  # already closed by ssock

        elapsed_ms = round((time.perf_counter() - start) * 1000)
        return max(elapsed_ms, 1)
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def batch_test_latency(proxies: list[dict]) -> list[dict]:
    """Test latency for all proxies concurrently. Returns proxies with delay field set."""
    total = len(proxies)
    print(f"\nTesting latency for {total} nodes ({MAX_WORKERS} concurrent)...")

    results = [None] * total
    alive_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(test_tcp_latency, p): i for i, p in enumerate(proxies)}
        done_count = 0
        for future in concurrent.futures.as_completed(future_map):
            idx = future_map[future]
            done_count += 1
            try:
                latency = future.result()
                results[idx] = latency
                if latency is not None:
                    alive_count += 1
            except Exception:
                results[idx] = None

            if done_count % 100 == 0 or done_count == total:
                print(f"  Progress: {done_count}/{total} tested, {alive_count} alive")

    # Update proxies with latency; filter dead and slow (>2s) nodes
    alive_proxies = []
    slow_count = 0
    for i, p in enumerate(proxies):
        latency = results[i]
        if latency is not None:
            if latency > MAX_DELAY_MS:
                slow_count += 1
                continue
            p["delay"] = latency
            alive_proxies.append(p)

    print(f"Latency test done: {alive_count}/{total} alive, {slow_count} removed (>{MAX_DELAY_MS}ms), {len(alive_proxies)} kept")
    return alive_proxies


def select_best_nodes(proxies: list[dict], max_nodes: int = MAX_NODES) -> list[dict]:
    """Select the best nodes with priority: EU/US first, fast response, diverse regions."""
    if len(proxies) <= max_nodes:
        return proxies

    # Categorize: priority regions vs others
    priority = []
    others = []
    for p in proxies:
        regions = classify_region(p["name"])
        if any(r in PRIORITY_REGIONS for r in regions):
            priority.append(p)
        else:
            others.append(p)

    # Sort each group: nodes with delay info first (lower delay = better),
    # then nodes without delay info
    def sort_key(p):
        delay = p.get("delay", 99999)
        if isinstance(delay, (int, float)):
            return delay
        return 99999

    priority.sort(key=sort_key)
    others.sort(key=sort_key)

    # Allocate: 60% to priority regions, 40% to others
    priority_quota = int(max_nodes * 0.6)
    others_quota = max_nodes - priority_quota

    selected_priority = priority[:priority_quota]
    selected_others = others[:others_quota]

    # If one group doesn't fill its quota, give remainder to the other
    if len(selected_priority) < priority_quota:
        extra = priority_quota - len(selected_priority)
        selected_others = others[:others_quota + extra]
    elif len(selected_others) < others_quota:
        extra = others_quota - len(selected_others)
        selected_priority = priority[:priority_quota + extra]

    result = selected_priority + selected_others
    print(f"Selected: {len(selected_priority)} priority (EU/US/CA/AU/UK/DE/FR) + {len(selected_others)} others = {len(result)} total")
    return result


# ============================================================
# Generate Clash Meta Config
# ============================================================

def generate_config(proxies: list[dict]) -> dict:
    """Generate complete Clash Meta config dict."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    all_names = [p["name"] for p in proxies]

    # Classify proxies into regions
    region_map = {}
    for rcode, (_kws, gname) in REGION_KEYWORDS.items():
        region_map[gname] = []

    for p in proxies:
        regions = classify_region(p["name"])
        for r in regions:
            if r in region_map:
                region_map[r].append(p["name"])

    # Only include region groups that have proxies
    active_regions = {k: v for k, v in region_map.items() if v}

    # Build proxy groups
    proxy_groups = [
        {
            "name": "🚀 选择代理",
            "type": "select",
            "proxies": ["♻ 自动选择", "🔰 延迟最低", "✅ 手动选择", "🗺️ 选择地区"],
        },
        {
            "name": "♻ 自动选择",
            "type": "fallback",
            "url": "https://www.google.com/",
            "interval": 300,
            "proxies": all_names,
        },
        {
            "name": "🔰 延迟最低",
            "type": "url-test",
            "url": "https://www.google.com/",
            "interval": 300,
            "tolerance": 20,
            "proxies": all_names,
        },
        {
            "name": "✅ 手动选择",
            "type": "select",
            "proxies": all_names,
        },
        {
            "name": "🌐 突破锁区",
            "type": "select",
            "proxies": ["DIRECT", "🚀 选择代理"],
        },
        {
            "name": "❓ 疑似国内",
            "type": "select",
            "proxies": ["DIRECT", "🚀 选择代理", "REJECT"],
        },
        {
            "name": "🐟 漏网之鱼",
            "type": "select",
            "proxies": ["DIRECT", "🚀 选择代理"],
        },
        {
            "name": "🚨 病毒网站",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"],
        },
        {
            "name": "⛔ 广告拦截",
            "type": "select",
            "proxies": ["REJECT", "DIRECT", "🚀 选择代理"],
        },
        {
            "name": "🗺️ 选择地区",
            "type": "select",
            "proxies": list(active_regions.keys()) if active_regions else ["✅ 手动选择"],
        },
    ]

    # Add region groups
    for gname, members in active_regions.items():
        proxy_groups.append({
            "name": gname,
            "type": "select",
            "proxies": members,
        })

    # Rules
    rules = [
        # Ad blocking
        "DOMAIN-SUFFIX,ads.google.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adservice.google.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,googleadservices.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,doubleclick.net,⛔ 广告拦截",
        "DOMAIN-SUFFIX,ad.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adnxs.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adsrvr.org,⛔ 广告拦截",
        "DOMAIN-SUFFIX,pgdt.ugdtimg.com,⛔ 广告拦截",
        "DOMAIN-KEYWORD,adservice,⛔ 广告拦截",
        "DOMAIN-KEYWORD,tracking,⛔ 广告拦截",
        # Malware
        "DOMAIN-SUFFIX,malware-site.example,🚨 病毒网站",
        # China direct
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,alipay.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "DOMAIN-SUFFIX,douyin.com,DIRECT",
        "DOMAIN-SUFFIX,toutiao.com,DIRECT",
        "DOMAIN-SUFFIX,csdn.net,DIRECT",
        "DOMAIN-SUFFIX,aliyun.com,DIRECT",
        "DOMAIN-SUFFIX,aliyuncs.com,DIRECT",
        "DOMAIN-SUFFIX,tencentcloud.com,DIRECT",
        "DOMAIN-SUFFIX,meituan.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,xiaomi.com,DIRECT",
        # Proxy
        "DOMAIN-SUFFIX,google.com,🚀 选择代理",
        "DOMAIN-SUFFIX,google.co.jp,🚀 选择代理",
        "DOMAIN-SUFFIX,googleapis.com,🚀 选择代理",
        "DOMAIN-SUFFIX,gstatic.com,🚀 选择代理",
        "DOMAIN-SUFFIX,youtube.com,🚀 选择代理",
        "DOMAIN-SUFFIX,ytimg.com,🚀 选择代理",
        "DOMAIN-SUFFIX,googlevideo.com,🚀 选择代理",
        "DOMAIN-SUFFIX,gmail.com,🚀 选择代理",
        "DOMAIN-SUFFIX,github.com,🚀 选择代理",
        "DOMAIN-SUFFIX,githubusercontent.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twitter.com,🚀 选择代理",
        "DOMAIN-SUFFIX,x.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twimg.com,🚀 选择代理",
        "DOMAIN-SUFFIX,facebook.com,🚀 选择代理",
        "DOMAIN-SUFFIX,fbcdn.net,🚀 选择代理",
        "DOMAIN-SUFFIX,instagram.com,🚀 选择代理",
        "DOMAIN-SUFFIX,whatsapp.com,🚀 选择代理",
        "DOMAIN-SUFFIX,telegram.org,🚀 选择代理",
        "DOMAIN-SUFFIX,t.me,🚀 选择代理",
        "DOMAIN-SUFFIX,wikipedia.org,🚀 选择代理",
        "DOMAIN-SUFFIX,reddit.com,🚀 选择代理",
        "DOMAIN-SUFFIX,netflix.com,🚀 选择代理",
        "DOMAIN-SUFFIX,nflxvideo.net,🚀 选择代理",
        "DOMAIN-SUFFIX,spotify.com,🚀 选择代理",
        "DOMAIN-SUFFIX,discord.com,🚀 选择代理",
        "DOMAIN-SUFFIX,discordapp.com,🚀 选择代理",
        "DOMAIN-SUFFIX,openai.com,🚀 选择代理",
        "DOMAIN-SUFFIX,claude.ai,🚀 选择代理",
        "DOMAIN-SUFFIX,anthropic.com,🚀 选择代理",
        "DOMAIN-SUFFIX,chatgpt.com,🚀 选择代理",
        "DOMAIN-SUFFIX,amazonaws.com,🚀 选择代理",
        "DOMAIN-SUFFIX,cloudflare.com,🚀 选择代理",
        "DOMAIN-SUFFIX,microsoft.com,🚀 选择代理",
        "DOMAIN-SUFFIX,apple.com,🚀 选择代理",
        "DOMAIN-SUFFIX,icloud.com,🚀 选择代理",
        "DOMAIN-SUFFIX,amazon.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twitch.tv,🚀 选择代理",
        "DOMAIN-SUFFIX,steam.com,🚀 选择代理",
        "DOMAIN-SUFFIX,steampowered.com,🚀 选择代理",
        "DOMAIN-SUFFIX,steamcommunity.com,🚀 选择代理",
        "DOMAIN-SUFFIX,pixiv.net,🚀 选择代理",
        "DOMAIN-SUFFIX,pximg.net,🚀 选择代理",
        "DOMAIN-SUFFIX,docker.com,🚀 选择代理",
        "DOMAIN-SUFFIX,docker.io,🚀 选择代理",
        "DOMAIN-SUFFIX,npmjs.org,🚀 选择代理",
        "DOMAIN-SUFFIX,pypi.org,🚀 选择代理",
        "DOMAIN-SUFFIX,huggingface.co,🚀 选择代理",
        "DOMAIN-SUFFIX,medium.com,🚀 选择代理",
        "DOMAIN-SUFFIX,stackoverflow.com,🚀 选择代理",
        # Region unlock
        "DOMAIN-SUFFIX,hulu.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,hbo.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,hbomax.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,disneyplus.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,disney-plus.net,🌐 突破锁区",
        "DOMAIN-SUFFIX,primevideo.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,dazn.com,🌐 突破锁区",
        # GeoIP & final
        "GEOIP,CN,❓ 疑似国内",
        "MATCH,🐟 漏网之鱼",
    ]

    config = {
        "# Update": now,
        "allow-lan": False,
        "mixed-port": 7890,
        "external-controller": "0.0.0.0:9090",
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "listen": ":1053",
            "ipv6": True,
            "nameserver": ["223.5.5.5", "114.114.114.114"],
            "fallback": ["8.8.8.8", "1.1.1.1"],
        },
        "sniffer": {
            "enable": True,
            "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.apple.com"],
            "sniff": {
                "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
                "TLS": {"ports": [443, 8443]},
            },
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
    }

    return config


def write_yaml(config: dict, output_path: str):
    """Write config to YAML file with header comment."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    # Remove the comment key and build the real config
    clean_config = {k: v for k, v in config.items() if not k.startswith("#")}

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Update: {now}\n")
        yaml.dump(
            clean_config,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=1000,
        )

    print(f"\nConfig written to: {output_path}")


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 60)
    print("  find_node - Free Proxy Node Collector")
    print("=" * 60)

    # Fetch all sources
    all_proxies = []
    for url in SUB_URLS:
        nodes = fetch_and_parse(url)
        all_proxies.extend(nodes)

    print(f"\nTotal raw nodes fetched: {len(all_proxies)}")

    if not all_proxies:
        print("ERROR: No nodes fetched. Check network or subscription URLs.")
        sys.exit(1)

    # Dedup
    proxies = dedup_proxies(all_proxies)
    print(f"After dedup: {len(proxies)} unique nodes")

    # Validate
    proxies = [p for p in proxies if validate_proxy(p)]
    print(f"After validation: {len(proxies)} valid nodes")

    # Clean up empty/None fields
    proxies = [clean_proxy(p) for p in proxies]

    # Filter excluded regions/keywords
    proxies = [p for p in proxies if not is_excluded(p)]
    print(f"After filtering CN/HK/TW/high-risk: {len(proxies)} nodes")

    # Test latency (TCP handshake) and remove dead nodes
    proxies = batch_test_latency(proxies)

    # Sort by latency
    proxies.sort(key=lambda p: p.get("delay", 99999))

    # Select best nodes (capped at MAX_NODES)
    proxies = select_best_nodes(proxies)

    # Add latency prefix to node names like "[xxms] name"
    for p in proxies:
        delay = p.get("delay", 0)
        orig_name = p["name"]
        # Strip existing delay prefix if any
        orig_name = re.sub(r"^\[\d+ms\]\s*", "", orig_name)
        p["name"] = f"[{delay}ms] {orig_name}"

    # Generate config
    config = generate_config(proxies)

    # Output
    output_path = "find_node.meta.yml"
    write_yaml(config, output_path)

    print(f"Done! {len(proxies)} nodes in config.")


if __name__ == "__main__":
    main()
