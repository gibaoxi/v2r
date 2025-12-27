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
# 参数
################################

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray/xray")
WORKDIR = "./tmp"
INPUT_FILE = "sub.txt"
OUTPUT_FILE = "ping.txt"

SOCKS_PORT_BASE = 20000
TIMEOUT = 10
MAX_WORKERS = 3

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
# 工具
################################

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

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
# 节点解析
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

    except Exception as e:
        return {
            "_type": "parse_error",
            "_raw": raw,
            "_err": str(e)
        }

################################
# Xray 配置
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
# 测试核心（可观测）
################################

def tcp_test(host, port):
    try:
        socket.create_connection((host, port), timeout=TIMEOUT).close()
        return True
    except:
        return False

def test_node(n, idx):
    port = SOCKS_PORT_BASE + idx

    if n.get("_type") == "parse_error":
        return False, f"parse_error {n.get('_err')}"

    if not port_free(port):
        return False, "port_busy"

    cfg_file = f"{WORKDIR}/{idx}.json"
    json.dump(build_xray_config(n, port), open(cfg_file, "w"))

    p = subprocess.Popen(
        [XRAY_BIN, "-c", cfg_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(1.5)

    if p.poll() is not None:
        err = p.stderr.read()
        return False, f"xray_exit {err[:200]}"

    tcp_targets = random.sample(TCP_TEST_HOSTS, 2)
    tcp_results = [(h, pt, tcp_test(h, pt)) for h, pt in tcp_targets]

    if not any(x[2] for x in tcp_results):
        p.terminate()
        return False, f"tcp_failed {tcp_results}"

    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }

    for url in random.sample(HTTP_TEST_URLS, 2):
        try:
            r = requests.get(url, proxies=proxies, timeout=TIMEOUT)
            if r.status_code in (200, 204):
                p.terminate()
                return True, "ok"
        except Exception as e:
            last_err = str(e)

    p.terminate()
    return False, f"http_failed {last_err}"

################################
# 主入口
################################

def main():
    clean_tmp()

    nodes = []
    with open(INPUT_FILE, encoding="utf-8") as f:
        for line in f:
            n = parse_node(line)
            if n:
                nodes.append(n)

    ok_nodes = []

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {
            ex.submit(test_node, n, i): n
            for i, n in enumerate(nodes)
        }

        for f in as_completed(futures):
            n = futures[f]
            try:
                res, reason = f.result()
                if res:
                    ok_nodes.append(n["_raw"])
                    log(f"OK  {n['_type']}")
                else:
                    log(f"BAD {n['_type']} -> {reason}")
            except Exception as e:
                log(f"ERROR {e}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for x in ok_nodes:
            f.write(x + "\n")

    log(f"完成：可用 {len(ok_nodes)}")

if __name__ == "__main__":
    main()
