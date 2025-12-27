#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import base64
import random
import socket
import time
import shutil
import subprocess
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

################################
# 原 xr.py 的全局参数（保留）
################################

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray/xray")
WORKDIR = "./tmp"
INPUT_FILE = "all_configs.txt"
OUTPUT_FILE = "ping.txt"

SOCKS_PORT_BASE = 20000
TIMEOUT = 6
MAX_WORKERS = 10

################################
# 升级版测试目标
################################

TCP_TEST_HOSTS = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
    ("www.cloudflare.com", 443),
    ("www.google.com", 443),
]

HTTP_TEST_URLS = [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.gstatic.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]

################################
# 工具（原结构 + 加强）
################################

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def clean_tmp():
    if os.path.exists(WORKDIR):
        shutil.rmtree(WORKDIR)
    os.makedirs(WORKDIR, exist_ok=True)

def port_free(port):
    try:
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.close()
        return True
    except:
        return False

################################
# 节点解析（= 原版 + 修正）
################################

def parse_node(line):
    raw = line.strip()
    if not raw:
        return None

    try:
        if raw.startswith("vmess://"):
            data = json.loads(base64.b64decode(raw[8:] + "===").decode())
            data["_type"] = "vmess"

        elif raw.startswith("vless://"):
            u = urlparse(raw)
            q = parse_qs(u.query)
            data = {
                "_type": "vless",
                "id": u.username,
                "host": u.hostname,
                "port": u.port,
                "security": q.get("security", ["none"])[0],
                "flow": q.get("flow", [""])[0],
                "sni": q.get("sni", [""])[0],
            }

        elif raw.startswith("trojan://"):
            u = urlparse(raw)
            q = parse_qs(u.query)
            data = {
                "_type": "trojan",
                "password": u.username,
                "host": u.hostname,
                "port": u.port,
                "sni": q.get("sni", [""])[0],
            }

        elif raw.startswith("ss://"):
            uri = raw[5:].split("#")[0]
            if "@" not in uri:
                decoded = base64.b64decode(uri + "===").decode()
                method_pass, server = decoded.split("@")
            else:
                method_pass, server = uri.split("@")
            method, password = method_pass.split(":")
            host, port = server.split(":")
            data = {
                "_type": "ss",
                "method": method,
                "password": password,
                "host": host,
                "port": int(port),
            }
        else:
            return None

        data["_raw"] = raw
        return data

    except Exception:
        return None

################################
# Xray 配置（沿用你原来的方式）
################################

def build_xray_config(n, port):
    if n["_type"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": n["add"],
                    "port": int(n["port"]),
                    "users": [{
                        "id": n["id"],
                        "alterId": int(n.get("aid", 0)),
                        "security": n.get("scy", "auto"),
                    }]
                }]
            }
        }

    elif n["_type"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": n["host"],
                    "port": n["port"],
                    "users": [{
                        "id": n["id"],
                        "flow": n["flow"],
                        "encryption": "none",
                    }]
                }]
            },
            "streamSettings": {
                "security": n["security"],
                "tlsSettings": {"serverName": n["sni"]}
            }
        }

    elif n["_type"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": n["host"],
                    "port": n["port"],
                    "password": n["password"],
                }]
            }
        }

    else:  # ss
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": n["host"],
                    "port": n["port"],
                    "method": n["method"],
                    "password": n["password"],
                }]
            }
        }

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
        }],
        "outbounds": [outbound]
    }

################################
# 测试（核心升级点）
################################

def tcp_test(host, port):
    try:
        socket.create_connection((host, port), timeout=TIMEOUT).close()
        return True
    except:
        return False

def http_test(port):
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    for url in random.sample(HTTP_TEST_URLS, 2):
        try:
            r = requests.get(url, proxies=proxies, timeout=TIMEOUT)
            if r.status_code in (200, 204):
                return True
        except:
            pass
    return False

def test_node(n, idx):
    port = SOCKS_PORT_BASE + idx
    if not port_free(port):
        return False

    cfg = build_xray_config(n, port)
    cfg_file = f"{WORKDIR}/{idx}.json"
    json.dump(cfg, open(cfg_file, "w"))

    p = subprocess.Popen(
        [XRAY_BIN, "-c", cfg_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(1.5)

    tcp_ok = any(
        tcp_test(h, p)
        for h, p in random.sample(TCP_TEST_HOSTS, 2)
    )

    http_ok = http_test(port) if tcp_ok else False

    p.terminate()
    p.wait(timeout=2)

    return tcp_ok and http_ok

################################
# 主入口（原风格）
################################

def main():
    clean_tmp()

    nodes = []
    with open(INPUT_FILE, encoding="utf-8") as f:
        for line in f:
            n = parse_node(line)
            if n:
                nodes.append(n)

    ok = []

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        tasks = {
            ex.submit(test_node, n, i): n
            for i, n in enumerate(nodes)
        }

        for f in as_completed(tasks):
            n = tasks[f]
            try:
                if f.result():
                    ok.append(n["_raw"])
                    log(f"OK  {n['_type']}")
                else:
                    log(f"BAD {n['_type']}")
            except:
                pass

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for line in ok:
            f.write(line + "\n")

    log(f"完成：可用 {len(ok)}")

if __name__ == "__main__":
    main()
