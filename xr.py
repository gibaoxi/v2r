#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xray 节点可用性测试（安全版）

判定规则：
1. TCP 直连测试 2 次（都成功）
2. HTTP 测试：从 N 个 URL 中随机选 2 个
   - 使用 HEAD
   - 任意 1 个成功即可

设计目标：
- 可在 GitHub Actions 长期运行
- 不测速、不下载、不并发 HTTP
- 尽量不触发节点风控
"""

import os
import json
import base64
import socket
import subprocess
import time
import random
import shutil
import logging
from urllib.parse import urlparse, parse_qs

import requests

# ==========================
# 基础配置
# ==========================

XRAY_BIN = "./xray/xray"
WORKDIR = "./xray_tmp"
SOCKS_PORT_BASE = 10800

TCP_TIMEOUT = 5
HTTP_TIMEOUT = 8

TCP_INTERVAL = 0.6        # 两次 TCP 间隔
XRAY_BOOT_WAIT = 2.0      # Xray 启动等待

HTTP_TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/favicon.ico",
]

# ==========================
# 日志配置
# ==========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger("xray-check")

os.makedirs(WORKDIR, exist_ok=True)

# ==========================
# 节点解析
# ==========================

def parse_node(line: str):
    """
    解析 sub.txt 中的节点
    目前支持：
    - vmess
    - vless (tls / reality)
    - trojan
    """
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
                "short_id": q.get("sid", [""])[0],
            }

        if line.startswith("trojan://"):
            u = urlparse(line)
            return {
                "type": "trojan",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username
            }
    except Exception as e:
        log.debug(f"节点解析失败: {e}")

    return None

# ==========================
# Xray 配置生成
# ==========================

def build_xray_config(node: dict, socks_port: int) -> dict:
    """
    构造最小可用 Xray 配置
    """
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [
            build_outbound(node),
            {"protocol": "freedom", "tag": "direct"}
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "outboundTag": "proxy"
            }]
        }
    }

def build_outbound(n: dict) -> dict:
    """
    根据节点类型生成 outbound
    """
    if n["type"] == "vmess":
        return {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": n["server"],
                    "port": n["port"],
                    "users": [{
                        "id": n["uuid"],
                        "alterId": 0,
                        "security": "auto"
                    }]
                }]
            },
            "streamSettings": {
                "security": "tls"
            } if n["tls"] else {}
        }

    if n["type"] == "vless":
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": n["server"],
                    "port": n["port"],
                    "users": [{
                        "id": n["uuid"],
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {}
        }

        if n["security"] in ("tls", "reality"):
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": n["sni"]
            }
            if n["security"] == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "publicKey": n["public_key"],
                    "shortId": n["short_id"]
                }

        return outbound

    if n["type"] == "trojan":
        return {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": n["server"],
                    "port": n["port"],
                    "password": n["password"]
                }]
            },
            "streamSettings": {"security": "tls"}
        }

    raise ValueError("不支持的节点类型")

# ==========================
# 测试函数
# ==========================

def tcp_test_twice(host: str, port: int) -> bool:
    """
    对节点做两次 TCP connect
    """
    for i in range(2):
        try:
            s = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
            s.close()
            time.sleep(TCP_INTERVAL)
        except Exception as e:
            log.debug(f"TCP 第 {i+1} 次失败: {e}")
            return False
    return True

def http_test_random_two(socks_port: int) -> bool:
    """
    从 URL 列表中随机选 2 个进行 HEAD 测试
    """
    urls = random.sample(HTTP_TEST_URLS, 2)
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}",
    }

    for url in urls:
        try:
            r = requests.head(
                url,
                proxies=proxies,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True
            )
            if r.status_code in (200, 204):
                return True
        except Exception as e:
            log.debug(f"HTTP 测试失败 {url}: {e}")

    return False

# ==========================
# 单节点测试流程
# ==========================

def test_single_node(index: int, line: str, node: dict):
    socks_port = SOCKS_PORT_BASE + index
    cfg_path = f"{WORKDIR}/{index}.json"

    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(build_xray_config(node, socks_port), f, indent=2)

    process = subprocess.Popen([XRAY_BIN, "run", "-config", cfg_path])
    time.sleep(XRAY_BOOT_WAIT)

    try:
        if not tcp_test_twice(node["server"], node["port"]):
            log.info(f"❌ TCP 不稳定: {node['server']}")
            return None

        if not http_test_random_two(socks_port):
            log.info(f"❌ HTTP 不通: {node['server']}")
            return None

        log.info(f"✅ 可用节点: {node['server']}")
        return line

    finally:
        process.terminate()
        process.wait()
        os.remove(cfg_path)

# ==========================
# 主流程
# ==========================

def main():
    with open("sub.txt", "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    ok_nodes = []

    for idx, line in enumerate(lines):
        node = parse_node(line)
        if not node:
            continue

        result = test_single_node(idx, line, node)
        if result:
            ok_nodes.append(result)

    with open("ping.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ok_nodes))

    shutil.rmtree(WORKDIR, ignore_errors=True)
    log.info(f"完成，可用节点 {len(ok_nodes)} 个")

if __name__ == "__main__":
    main()
