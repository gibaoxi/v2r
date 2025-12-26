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

DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1048576"  # 1MB = 1048576 bytes


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
            "publicKey": q.get("pbk", [""])[0],
            "shortId": q.get("sid", [""])[0],
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
        try:
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
        except:
            return None

    if line.startswith("ss://"):
        raw = line[5:]
        if "@" not in raw:
            try:
                raw = base64.b64decode(raw + "==").decode()
            except:
                return None
        
        try:
            if "@" not in raw:
                return None
                
            method_pass, server = raw.split("@", 1)
            if ":" not in method_pass:
                return None
                
            method, password = method_pass.split(":", 1)
            
            # 处理服务器部分（可能有多个冒号的情况）
            server_parts = server.split(":")
            if len(server_parts) < 2:
                return None
                
            host = server_parts[0]
            port = int(server_parts[1])
            
            return {
                "type": "ss",
                "server": host,
                "port": port,
                "method": method,
                "password": password
            }
        except (ValueError, IndexError):
            return None

    return None


# ---------------- 生成 Xray 配置 ----------------
def gen_config(n):
    outbound = {}

    if n["type"] == "vless":
        # 基础配置
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
                "security": n["security"]
            }
        }
        
        # TLS设置
        if n["security"] == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": n.get("sni", n["server"])
            }
        # REALITY设置
        elif n["security"] == "reality":
            outbound["streamSettings"]["realitySettings"] = {
                "show": False,
                "fingerprint": "chrome",
                "serverName": n.get("sni", n["server"]),
                "publicKey": n.get("publicKey", ""),
                "shortId": n.get("shortId", ""),
                "spiderX": n.get("spiderX", "/")
            }
        
        # WebSocket设置
        if n["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": n.get("path", ""),
                "headers": {"Host": n.get("host", n["server"])}
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
    
    best_http_delay = -1  # 初始化最佳HTTP延时
    
    for u in HTTP_TEST_URLS:
        try:
            start_time = time.time()
            r = requests.get(u, proxies=proxies, timeout=8)
            http_delay = int((time.time() - start_time) * 1000)  # 计算延时（毫秒）
            
            if r.status_code in (200, 204):
                # 记录最佳HTTP延时（最小的延时）
                if best_http_delay == -1 or http_delay < best_http_delay:
                    best_http_delay = http_delay
                return True, best_http_delay
        except:
            pass
    
    return False, -1


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
        
        # 记录开始下载的时间
        download_start = time.time()
        
        for c in r.iter_content(8192):
            size += len(c)
            if size >= 1048576:  # 下载1MB后停止
                break
        
        # 计算下载1MB所需的时间
        download_time = time.time() - download_start
        
        # 计算下载速度（Mbps）
        speed = round((size * 8) / (download_time * 1024 * 1024), 2) if download_time > 0 else 0
        
        return speed, round(download_time, 2)
    except:
        return 0, -1  # 下载失败


# ---------------- 主流程 ----------------
results = []

with open("sub.txt", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
            
        try:
            node = parse_node(line)
            if not node:
                print(f"跳过无法解析的节点: {line[:50]}...")
                continue

            ok, tcp_ms = tcp_test(node["server"], node["port"])
            if not ok:
                print(f"TCP测试失败: {node['server']}:{node['port']}")
                continue

            config = gen_config(node)
            with open(CONFIG, "w") as c:
                json.dump(config, c, indent=2)

            p = subprocess.Popen([XRAY_BIN, "run", "-config", CONFIG])
            time.sleep(3)

            http_ok, http_ms = http_test()
            if not http_ok:
                p.terminate()
                print(f"HTTP测试失败: {node['server']}")
                continue

            speed, download_time = speed_test()
            p.terminate()

            # 只要下载成功（不管速度多慢）就保留节点
            if download_time > 0:
                # 保存节点链接、TCP延时、HTTP延时、下载速度和下载时间
                results.append((line, tcp_ms, http_ms, speed, download_time))
                print(f"节点可用: {node['server']}, TCP延时: {tcp_ms}ms, HTTP延时: {http_ms}ms, 速度: {speed}Mbps, 下载1MB时间: {download_time}s")
            else:
                print(f"下载测试失败: {node['server']}")
                
        except Exception as e:
            print(f"处理节点时出错: {line[:30]}... 错误: {str(e)}")
            continue

# 排序：速度优先，其次TCP延迟，然后HTTP延迟
results.sort(key=lambda x: (-x[3], x[1], x[2]))

# 保存结果到ping.txt
with open("ping.txt", "w", encoding="utf-8") as f:
    for r in results:
        f.write(r[0] + "\n")

# 保存详细结果到detailed_results.txt
with open("detailed_results.txt", "w", encoding="utf-8") as f:
    f.write("节点链接\tTCP延时(ms)\tHTTP延时(ms)\t速度(Mbps)\t下载1MB时间(s)\n")
    for r in results:
        f.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}\n")

print(f"可用节点数: {len(results)}")
print("详细结果已保存到 detailed_results.txt")
