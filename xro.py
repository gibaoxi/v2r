#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import socket
import subprocess
import threading
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================== 基本配置 ==================
XRAY_BIN = "./xray/xray"
SUB_FILE = "sub.txt"
GOOD_FILE = "ping.txt"
BAD_FILE = "bad.txt"

MAX_WORKERS = 3
TCP_TIMEOUT = 10
HTTP_TIMEOUT = 10
SOCKS_BASE = 30000

HTTP_TEST_URLS = [
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
]

lock = threading.Lock()

# ================== Xray 验证 ==================
if not os.path.exists(XRAY_BIN):
    print(f"[FATAL] Xray 不存在: {XRAY_BIN}")
    sys.exit(1)
if not os.access(XRAY_BIN, os.X_OK):
    print(f"[FATAL] Xray 无执行权限: {XRAY_BIN}")
    print("请执行: chmod +x ./xray/xray")
    sys.exit(1)
print(f"[INFO] Xray 可执行文件验证通过：{XRAY_BIN}")

# ================== 工具函数 ==================
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def tcp_test(host, port):
    """两次 TCP 测试，只要有一次成功就通过"""
    reasons = []
    for _ in range(2):
        try:
            with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
                return True, ""
        except Exception as e:
            reasons.append(str(e))
    return False, "; ".join(reasons)

# ================== SS 解析 ==================
def parse_ss(raw):
    uri = raw[5:]
    if "#" in uri:
        uri = uri.split("#", 1)[0]
    if "@" not in uri:
        uri = base64.b64decode(uri + "===").decode()
    userinfo, server = uri.rsplit("@", 1)
    method, password = userinfo.split(":", 1)
    host, port = server.rsplit(":", 1)
    return {
        "_type": "ss",
        "host": host,
        "port": int(port),
        "method": method,
        "password": password,
        "_raw": raw
    }

# ================== 节点解析（startswith） ==================
def parse_node(raw):
    try:
        raw = raw.strip()
        if not raw:
            return None
        if raw.startswith("ss://"):
            return parse_ss(raw)
        if raw.startswith("vmess://"):
            cfg = json.loads(base64.b64decode(raw[8:] + "===").decode())
            return {
                "_type": "vmess",
                "host": cfg["add"],
                "port": int(cfg["port"]),
                "uuid": cfg["id"],
                "aid": int(cfg.get("aid", 0)),
                "_raw": raw
            }
        if raw.startswith("vless://"):
            body = raw[8:].split("#", 1)[0]
            user, rest = body.split("@", 1)
            host, port = rest.split(":", 1)
            return {
                "_type": "vless",
                "host": host,
                "port": int(port),
                "uuid": user,
                "_raw": raw
            }
        if raw.startswith("trojan://"):
            body = raw[9:].split("#", 1)[0]
            pwd, rest = body.split("@", 1)
            host, port = rest.split(":", 1)
            return {
                "_type": "trojan",
                "host": host,
                "port": int(port),
                "password": pwd,
                "_raw": raw
            }
        return None
    except:
        return None

# ================== Xray 配置生成 ==================
def gen_xray_cfg(n, port):
    inbound = {"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}
    if n["_type"] == "ss":
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": n["host"], "port": n["port"], "method": n["method"], "password": n["password"]}]}}
    elif n["_type"] == "vmess":
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": n["host"], "port": n["port"], "users": [{"id": n["uuid"], "alterId": n["aid"]}]}]}}
    elif n["_type"] == "vless":
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": n["host"], "port": n["port"], "users": [{"id": n["uuid"], "encryption": "none"}]}]}}
    elif n["_type"] == "trojan":
        outbound = {"protocol": "trojan", "settings": {"servers": [{"address": n["host"], "port": n["port"], "password": n["password"]}]}}
    return {"log": {"loglevel": "warning"}, "inbounds": [inbound], "outbounds": [outbound]}

# ================== HTTP 测试 ==================
def http_test(port):
    """随机选择两个 URL 测试 HTTP 代理"""
    proxies = {"http": f"socks5h://127.0.0.1:{port}"}
    urls = random.sample(HTTP_TEST_URLS, min(2, len(HTTP_TEST_URLS)))
    reasons = []
    for url in urls:
        try:
            r = requests.get(url, proxies=proxies, timeout=HTTP_TIMEOUT)
            if r.status_code in (200, 204):
                return True
        except Exception as e:
            reasons.append(str(e))
    return False

# ================== 单节点测试 ==================
def test_node(n, idx):
    ok, err = tcp_test(n["host"], n["port"])
    if not ok:
        return False, f"tcp_failed {err}"

    cfg_path = f"/tmp/xray_{idx}.json"
    socks_port = SOCKS_BASE + idx

    with open(cfg_path, "w") as f:
        json.dump(gen_xray_cfg(n, socks_port), f)

    p = subprocess.Popen([XRAY_BIN, "-config", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    try:
        if n["_type"] == "vless":  # TLS 节点只做 TCP
            return True, "tcp_only_tls"
        if http_test(socks_port):
            return True, "http_ok"
        return False, "http_failed"
    finally:
        p.terminate()
        p.wait(timeout=2)

# ================== 主程序 ==================
def main():
    raws = []
    with open(SUB_FILE, encoding="utf-8", errors="ignore") as f:
        for line in f:
            raws.extend(line.strip().split())

    nodes = []
    for r in raws:
        n = parse_node(r)
        if n:
            nodes.append(n)

    log(f"加载节点 {len(nodes)}")

    good, bad = [], []

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {ex.submit(test_node, n, i): n for i, n in enumerate(nodes)}
        for fut in as_completed(futures):
            n = futures[fut]
            try:
                ok, reason = fut.result()
            except Exception as e:
                ok, reason = False, f"exception {e}"

            with lock:
                if ok:
                    log(f"OK  {n['_type']} -> {reason}")
                    good.append(n["_raw"])
                else:
                    log(f"BAD {n['_type']} -> {reason}")
                    bad.append(f"{n['_raw']}  # {reason}")

    with open(GOOD_FILE, "w") as f:
        f.write("\n".join(good))

    with open(BAD_FILE, "w") as f:
        f.write("\n".join(bad))

    log(f"完成：可用 {len(good)} / {len(nodes)}")

if __name__ == "__main__":
    main()
