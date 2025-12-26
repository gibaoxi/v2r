#!/usr/bin/env python3
import socket
import time
import json
import subprocess
import requests
from urllib.parse import urlparse, parse_qs
import base64
import os

XRAY_BIN = "./xray/xray"
CONFIG = "./config.json"
SOCKS_PORT = 10808

HTTP_TEST_URLS = [
    "https://www.google.com/generate_204",
    "https://cloudflare.com"
]

DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=800000"


# ---------------- TCP 测试 ----------------
def tcp_test(host, port, timeout=5):
    try:
        start = time.time()
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, int((time.time() - start) * 1000)
    except:
        return False, -1


# ---------------- 解析节点 ----------------
def parse_node(line):
    if line.startswith("vless://"):
        u = urlparse(line)
        q = parse_qs(u.query)
        return {
            "type": "vless",
            "server": u.hostname,
            "port": u.port or 443,
            "uuid": u.username,
            "network": q.get("type", ["tcp"])[0],
            "security": q.get("security", [""])[0],
            "sni": q.get("sni", [u.hostname])[0],
            "host": q.get("host", [u.hostname])[0],
            "path": q.get("path", [""])[0],
        }

    if line.startswith("trojan://"):
        u = urlparse(line)
        return {
            "type": "trojan",
            "server": u.hostname,
            "port": u.port or 443,
            "password": u.username,
        }

    if line.startswith("vmess://"):
        data = base64.b64decode(line[8:] + "==").decode()
        j = json.loads(data)
        return {
            "type": "vmess",
            "server": j["add"],
            "port": int(j["port"]),
            "uuid": j["id"],
            "network": j.get("net", "tcp"),
            "host": j.get("host", ""),
            "path": j.get("path", ""),
            "tls": j.get("tls", "")
        }

    if line.startswith("ss://"):
        raw = line[5:]
        if "@" not in raw:
            raw = base64.b64decode(raw + "==").decode()
        method_pass, server = raw.split("@")
        method, password = method_pass.split(":")
        host, port = server.split(":")
        return {
            "type": "ss",
            "server": host,
            "port": int(port),
            "method": method,
            "password": password
        }

    return None


# ---------------- 生成 Xray 配置 ----------------
def gen_config(n):
    outbound = {}

    if n["type"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": n["server"],
                    "port": n["port"],
                    "users": [{"id": n["uuid"], "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": n["network"],
                "security": n["security"],
                "tlsSettings": {"serverName": n["sni"]} if n["security"] == "tls" else {},
                "wsSettings": {
                    "path": n["path"],
                    "headers": {"Host": n["host"]}
                } if n["network"] == "ws" else {}
            }
        }

    elif n["type"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": n["server"],
                    "port": n["port"],
                    "password": n["password"]
                }]
            }
        }

    elif n["type"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": n["server"],
                    "port": n["port"],
                    "users": [{"id": n["uuid"], "alterId": 0}]
                }]
            }
        }

    elif n["type"] == "ss":
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": n["server"],
                    "port": n["port"],
                    "method": n["method"],
                    "password": n["password"]
                }]
            }
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": SOCKS_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }


# ---------------- HTTP 测试 ----------------
def http_test():
    proxies = {
        "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"
    }
    for u in HTTP_TEST_URLS:
        try:
            r = requests.get(u, proxies=proxies, timeout=8)
            if r.status_code in (200, 204):
                return True
        except:
            pass
    return False


# ---------------- 下载测速 ----------------
def speed_test():
    proxies = {
        "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"
    }
    try:
        start = time.time()
        r = requests.get(DOWNLOAD_URL, proxies=proxies, stream=True, timeout=15)
        size = 0
        for c in r.iter_content(8192):
            size += len(c)
            if size > 800000:
                break
        t = time.time() - start
        return round((size * 8) / (t * 1024 * 1024), 2)
    except:
        return 0


# ---------------- 主流程 ----------------
results = []

with open("sub.txt", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        node = parse_node(line)
        if not node:
            continue

        ok, tcp_ms = tcp_test(node["server"], node["port"])
        if not ok:
            continue

        with open(CONFIG, "w") as c:
            json.dump(gen_config(node), c, indent=2)

        p = subprocess.Popen([XRAY_BIN, "run", "-config", CONFIG])
        time.sleep(3)

        if not http_test():
            p.terminate()
            continue

        speed = speed_test()
        p.terminate()

        if speed > 0.1:
            results.append((line, tcp_ms, speed))

# 排序：速度优先，其次延迟
results.sort(key=lambda x: (-x[2], x[1]))

with open("ping.txt", "w", encoding="utf-8") as f:
    for r in results:
        f.write(r[0] + "\n")

print("可用节点数:", len(results))
