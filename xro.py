#!/usr/bin/env python3
import os
import json
import time
import base64
import socket
import threading
import subprocess
import requests
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================== 配置 ==================
XRAY_BIN = "./xray/all_configs.txt"          # xray 路径
ALL_CONFIGS = "sub.txt"      # 改成 sub.txt
GOOD_FILE = "ping.txt"
BAD_FILE = "bad.txt"

SOCKS_PORT_BASE = 20000
MAX_WORKERS = 3               # 并发 3
TCP_TIMEOUT = 10              # TCP 超时 10 秒
HTTP_TIMEOUT = 10             # HTTP 超时 10 秒

HTTP_TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
]

lock = threading.Lock()

# ================== 工具 ==================
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def tcp_ping(host, port, timeout=TCP_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except Exception as e:
        return False, str(e)

# ================== SS 解析 ==================
def parse_ss(raw):
    uri = raw[5:]
    if "#" in uri:
        uri = uri.split("#", 1)[0]
    if "?" in uri:
        uri = uri.split("?", 1)[0]
    if "@" not in uri:
        decoded = base64.b64decode(uri + "===").decode()
        userinfo, server = decoded.rsplit("@", 1)
    else:
        userinfo, server = uri.rsplit("@", 1)
    method, password = userinfo.split(":", 1)
    host, port = server.rsplit(":", 1)
    return {
        "_type": "ss",
        "method": method,
        "password": password,
        "host": host,
        "port": int(port),
    }

# ================== 节点解析 ==================
def parse_node(raw):
    raw = raw.strip()
    if not raw:
        return None
    try:
        if raw.startswith("ss://"):
            data = parse_ss(raw)
        elif raw.startswith("vmess://"):
            cfg = json.loads(base64.b64decode(raw[8:] + "===").decode())
            data = {
                "_type": "vmess",
                "host": cfg["add"],
                "port": int(cfg["port"]),
                "uuid": cfg["id"],
                "alterId": int(cfg.get("aid", 0)),
                "net": cfg.get("net", "tcp"),
                "tls": cfg.get("tls", ""),
            }
        elif raw.startswith("vless://"):
            body = raw[8:]
            if "#" in body:
                body = body.split("#", 1)[0]
            user, rest = body.split("@", 1)
            hostport, *_ = rest.split("?")
            host, port = hostport.rsplit(":", 1)
            data = {
                "_type": "vless",
                "uuid": user,
                "host": host,
                "port": int(port),
                "security": "tls" if "security=tls" in raw or "reality" in raw else "",
            }
        elif raw.startswith("trojan://"):
            body = raw[9:]
            if "#" in body:
                body = body.split("#", 1)[0]
            passwd, rest = body.split("@", 1)
            host, port = rest.rsplit(":", 1)
            data = {
                "_type": "trojan",
                "password": passwd,
                "host": host,
                "port": int(port),
            }
        else:
            return None
        data["_raw"] = raw
        return data
    except Exception:
        return None

# ================== Xray 配置 ==================
def gen_xray_config(n, port):
    inbound = {"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}
    if n["_type"] == "ss":
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": n["host"], "port": n["port"], "method": n["method"], "password": n["password"]}]}}
    elif n["_type"] == "vmess":
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": n["host"], "port": n["port"], "users": [{"id": n["uuid"], "alterId": n["alterId"]}]}]}}
    elif n["_type"] == "vless":
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": n["host"], "port": n["port"], "users": [{"id": n["uuid"], "encryption": "none"}]}]}}
    elif n["_type"] == "trojan":
        outbound = {"protocol": "trojan", "settings": {"servers": [{"address": n["host"], "port": n["port"], "password": n["password"]}]}}
    return {"log": {"loglevel": "warning"}, "inbounds": [inbound], "outbounds": [outbound]}

# ================== HTTP 测试 ==================
def http_test(port):
    proxies = {"http": f"socks5h://127.0.0.1:{port}"}
    for url in HTTP_TEST_URLS:
        try:
            r = requests.get(url, proxies=proxies, timeout=HTTP_TIMEOUT)
            if r.status_code in (200, 204):
                return True
        except Exception:
            continue
    return False

# ================== 节点测试 ==================
def test_node(n, idx):
    try:
        host = n["host"]
        port = n["port"]
        ok, err = tcp_ping(host, port)
        if not ok:
            return False, f"tcp_failed {err}"
        # TLS / Reality 只做 TCP
        if n["_type"] == "vless" and n.get("security"):
            return True, "tcp_only_tls"
        socks_port = SOCKS_PORT_BASE + idx
        cfg_file = f"/tmp/xray_{idx}.json"
        with open(cfg_file, "w") as f:
            json.dump(gen_xray_config(n, socks_port), f)
        p = subprocess.Popen([XRAY_BIN, "-config", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if http_test(socks_port):
            return True, "http_ok"
        else:
            return False, "http_failed"
    except Exception as e:
        return False, f"exception {str(e)}"
    finally:
        try:
            p.terminate()
            p.wait(timeout=3)
        except:
            pass

# ================== 主流程 ==================
def main():
    if not os.path.exists(XRAY_BIN):
        log("ERROR: xray binary not found")
        return
    with open(ALL_CONFIGS) as f:
        raws = f.readlines()
    nodes = [parse_node(r) for r in raws]
    nodes = [n for n in nodes if n]
    log(f"加载节点 {len(nodes)}")
    good, bad = [], []
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        tasks = {ex.submit(test_node, n, i): n for i, n in enumerate(nodes)}
        for fut in as_completed(tasks):
            n = tasks[fut]
            try:
                res = fut.result()
                if isinstance(res, tuple):
                    ok, reason = res
                else:
                    ok, reason = False, f"bad_return {res}"
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
