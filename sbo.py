#!/usr/bin/env python3
import socket
import time
import json
import subprocess
import requests
import base64
import os
import concurrent.futures
import shutil
import logging
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Tuple, Optional

# ================== 基础配置 ==================
SINGBOX_BIN = "./sing-box/sing-box"
CONFIG_DIR = "./temp_configs"
SOCKS_PORT_BASE = 10808

TCP_TIMEOUT = 6
HTTP_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 45

MAX_WORKERS = 2
MAX_TOTAL_TIME = 300

HTTP_TEST_URL = "https://www.gstatic.com/generate_204"
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=3000000"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger("singbox-test")

os.makedirs(CONFIG_DIR, exist_ok=True)

# ================== 节点解析 ==================
def parse_node(line: str) -> Optional[Dict[str, Any]]:
    try:
        if line.startswith("vmess://"):
            raw = base64.b64decode(line[8:] + "==").decode()
            j = json.loads(raw)
            return {
                "type": "vmess",
                "server": j["add"],
                "port": int(j["port"]),
                "uuid": j["id"],
                "tls": j.get("tls") == "tls"
            }

        if line.startswith("vless://"):
            u = urlparse(line)
            q = parse_qs(u.query)
            return {
                "type": "vless",
                "server": u.hostname,
                "port": u.port or 443,
                "uuid": u.username,
                "security": q.get("security", [""])[0],
                "sni": q.get("sni", [u.hostname])[0],
                "public_key": q.get("pbk", [""])[0],
                "short_id": q.get("sid", [""])[0]
            }

        if line.startswith("trojan://"):
            u = urlparse(line)
            return {
                "type": "trojan",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username
            }

        if line.startswith("ss://"):
            raw = line[5:].split("#")[0]
            if "@" not in raw:
                raw = base64.b64decode(raw + "==").decode()
            method_pwd, server = raw.split("@")
            method, pwd = method_pwd.split(":")
            host, port = server.split(":")
            return {
                "type": "ss",
                "server": host,
                "port": int(port),
                "method": method,
                "password": pwd
            }

        if line.startswith(("hy2://", "hysteria2://")):
            clean = line.replace("hysteria2://", "").replace("hy2://", "")
            uid, addr = clean.split("@")
            host, port = addr.split(":")
            return {
                "type": "hysteria2",
                "server": host,
                "port": int(port),
                "password": uid
            }
    except:
        return None
    return None

# ================== sing-box 配置 ==================
def make_config(node: Dict[str, Any], port: int) -> Dict[str, Any]:
    outbound = make_outbound(node)
    outbound["tag"] = "proxy"

    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": port
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "final": "proxy"
        }
    }

def make_outbound(n: Dict[str, Any]) -> Dict[str, Any]:
    t = n["type"]

    if t == "vmess":
        o = {
            "type": "vmess",
            "server": n["server"],
            "server_port": n["port"],
            "uuid": n["uuid"]
        }
        if n["tls"]:
            o["tls"] = {"enabled": True}
        return o

    if t == "vless":
        o = {
            "type": "vless",
            "server": n["server"],
            "server_port": n["port"],
            "uuid": n["uuid"]
        }
        if n["security"] in ("tls", "reality"):
            o["tls"] = {
                "enabled": True,
                "server_name": n["sni"],
                "reality": {
                    "enabled": n["security"] == "reality",
                    "public_key": n["public_key"],
                    "short_id": n["short_id"]
                }
            }
        return o

    if t == "trojan":
        return {
            "type": "trojan",
            "server": n["server"],
            "server_port": n["port"],
            "password": n["password"],
            "tls": {"enabled": True}
        }

    if t == "ss":
        return {
            "type": "shadowsocks",
            "server": n["server"],
            "server_port": n["port"],
            "method": n["method"],
            "password": n["password"]
        }

    if t == "hysteria2":
        return {
            "type": "hysteria2",
            "server": n["server"],
            "server_port": n["port"],
            "password": n["password"],
            "tls": {"enabled": True}
        }

    return {"type": "direct"}

# ================== 测试函数 ==================
def tcp_test(host: str, port: int) -> int:
    s = socket.socket()
    s.settimeout(TCP_TIMEOUT)
    t = time.time()
    s.connect((host, port))
    s.close()
    return int((time.time() - t) * 1000)

def http_test(port: int) -> int:
    p = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}"
    }
    t = time.time()
    r = requests.get(HTTP_TEST_URL, proxies=p, timeout=HTTP_TIMEOUT)
    if r.status_code == 204:
        return int((time.time() - t) * 1000)
    raise RuntimeError()

def download_test(port: int) -> float:
    p = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}"
    }
    r = requests.get(DOWNLOAD_URL, proxies=p, stream=True, timeout=DOWNLOAD_TIMEOUT)
    size = 0
    start = time.time()
    for c in r.iter_content(8192):
        size += len(c)
        if size > 1024 * 1024:
            break
    return round(size / (time.time() - start) / 1024, 2)

# ================== 主流程 ==================
def run_node(idx: int, line: str, node: Dict[str, Any]) -> Optional[str]:
    port = SOCKS_PORT_BASE + idx
    cfg = make_config(node, port)
    path = f"{CONFIG_DIR}/{idx}.json"

    with open(path, "w") as f:
        json.dump(cfg, f)

    p = subprocess.Popen([SINGBOX_BIN, "run", "-c", path])
    time.sleep(2)

    try:
        tcp = tcp_test(node["server"], node["port"])
        http = http_test(port)

        speed = 0
        if node["type"] in ("ss", "hysteria2"):
            speed = download_test(port)

        log.info(f"✅ {node['server']} tcp={tcp}ms http={http}ms speed={speed}")
        return line
    except:
        log.info(f"❌ {node['server']} failed")
        return None
    finally:
        p.terminate()
        p.wait()
        os.remove(path)

def main():
    with open("sub.txt") as f:
        lines = [l.strip() for l in f if l.strip()]

    nodes = [(l, parse_node(l)) for l in lines]
    nodes = [(l, n) for l, n in nodes if n]

    ok = []
    with concurrent.futures.ThreadPoolExecutor(MAX_WORKERS) as ex:
        fs = [ex.submit(run_node, i, l, n) for i, (l, n) in enumerate(nodes)]
        for f in concurrent.futures.as_completed(fs):
            r = f.result()
            if r:
                ok.append(r)

    with open("ping.txt", "w") as f:
        f.write("\n".join(ok))

    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    log.info(f"🎉 完成，可用节点 {len(ok)} 个")

if __name__ == "__main__":
    main()
