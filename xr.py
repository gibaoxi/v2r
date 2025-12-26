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
    "https://captive.apple.com/hotspot-detect.html",
    "https://connectivitycheck.gstatic.com/generate_204"
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
    - ss (shadowsocks)
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
                "flow": q.get("flow", [""])[0],
            }

        if line.startswith("trojan://"):
            u = urlparse(line)
            q = parse_qs(u.query)
            return {
                "type": "trojan",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username,
                "sni": q.get("sni", [u.hostname])[0]
            }
            
        if line.startswith("ss://"):
            # 处理 shadowsocks 协议
            try:
                # 去掉协议头
                ss_part = line[5:]
                if "#" in ss_part:
                    ss_part = ss_part.split("#")[0]
                    
                # 处理 base64 编码
                if "@" in ss_part:
                    # 标准格式: method:password@server:port
                    if ":" not in ss_part.split("@")[0]:
                        # base64 编码的用户信息
                        user_info = base64.b64decode(ss_part.split("@")[0] + "==").decode()
                        server_part = ss_part.split("@")[1]
                        method, password = user_info.split(":", 1)
                    else:
                        # 明文格式
                        user_server = ss_part.split("//")[-1]
                        method_password, server_port = user_server.split("@", 1)
                        method, password = method_password.split(":", 1)
                else:
                    # 整个都是 base64
                    decoded = base64.b64decode(ss_part.split("#")[0] + "==").decode()
                    method_password, server_port = decoded.rsplit("@", 1)
                    method, password = method_password.split(":", 1)
                
                server, port = server_port.split(":", 1)
                port = int(port)
                
                return {
                    "type": "shadowsocks",
                    "server": server,
                    "port": port,
                    "method": method,
                    "password": password
                }
            except Exception as e:
                log.debug(f"SS 节点解析失败: {e}")
                return None
                
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
            "settings": {
                "udp": False,
                "auth": "noauth"
            }
        }],
        "outbounds": [
            build_outbound(node),
            {"protocol": "freedom", "tag": "direct"}
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "outboundTag": "proxy",
                "inboundTag": ["socks"]
            }]
        }
    }

def build_outbound(n: dict) -> dict:
    """
    根据节点类型生成 outbound
    """
    if n["type"] == "vmess":
        outbound = {
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
                "network": "tcp"
            }
        }
        
        if n["tls"]:
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": n["server"]
            }
            
        return outbound

    elif n["type"] == "vless":
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": n["server"],
                    "port": n["port"],
                    "users": [{
                        "id": n["uuid"],
                        "encryption": "none",
                        "flow": n.get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp"
            }
        }

        if n["security"] in ("tls", "reality"):
            outbound["streamSettings"]["security"] = n["security"]
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": n["sni"]
            }
            
            if n["security"] == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "show": False,
                    "fingerprint": "chrome",
                    "serverName": n["sni"],
                    "publicKey": n["public_key"],
                    "shortId": n["short_id"]
                }

        return outbound

    elif n["type"] == "trojan":
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
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "serverName": n.get("sni", n["server"])
                }
            }
        }
        
    elif n["type"] == "shadowsocks":
        return {
            "tag": "proxy",
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

    raise ValueError(f"不支持的节点类型: {n['type']}")

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
            if i == 0:  # 第一次成功后稍作延迟
                time.sleep(TCP_INTERVAL)
        except Exception as e:
            log.debug(f"TCP 第 {i+1} 次失败 {host}:{port} - {e}")
            return False
    return True

def http_test_random_two(socks_port: int) -> bool:
    """
    从 URL 列表中随机选 2 个进行 HEAD 测试
    """
    urls = random.sample(HTTP_TEST_URLS, 2)
    proxies = {
        "http": f"socks5://127.0.0.1:{socks_port}",
        "https": f"socks5://127.0.0.1:{socks_port}",
    }

    for url in urls:
        try:
            # 使用 GET 而不是 HEAD，因为某些网站可能不支持 HEAD
            r = requests.get(
                url,
                proxies=proxies,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                stream=True  # 不下载内容
            )
            r.close()  # 立即关闭连接
            
            if r.status_code in (200, 204, 301, 302):
                log.debug(f"HTTP 测试成功: {url}")
                return True
                
        except Exception as e:
            log.debug(f"HTTP 测试失败 {url}: {e}")

    return False

# ==========================
# 订阅文件处理
# ==========================

def decode_subscription(content: str) -> list:
    """
    处理订阅内容，可能是 base64 编码的
    """
    lines = []
    
    # 尝试直接按行分割
    direct_lines = [line.strip() for line in content.splitlines() if line.strip()]
    
    # 检查是否有明显的协议头
    has_protocol = any(line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://')) 
                      for line in direct_lines)
    
    if has_protocol:
        return direct_lines
    
    # 如果没有明显协议头，尝试 base64 解码
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        return decoded_lines
    except:
        pass
    
    # 如果都不行，返回原始内容
    return direct_lines

# ==========================
# 单节点测试流程
# ==========================

def test_single_node(index: int, line: str, node: dict):
    """
    测试单个节点
    """
    socks_port = SOCKS_PORT_BASE + index
    cfg_path = f"{WORKDIR}/config_{index}.json"
    
    log.info(f"测试节点 {index+1}: {node['server']}:{node['port']} ({node['type']})")

    try:
        # 生成 Xray 配置
        config = build_xray_config(node, socks_port)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        # 启动 Xray
        process = subprocess.Popen(
            [XRAY_BIN, "run", "-config", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(XRAY_BOOT_WAIT)

        # 检查进程是否正常运行
        if process.poll() is not None:
            log.info(f"❌ Xray 启动失败: {node['server']}")
            return None

        # 执行测试
        if not tcp_test_twice(node["server"], node["port"]):
            log.info(f"❌ TCP 连接失败: {node['server']}")
            return None

        if not http_test_random_two(socks_port):
            log.info(f"❌ HTTP 代理失败: {node['server']}")
            return None

        log.info(f"✅ 可用节点: {node['server']}")
        return line

    except Exception as e:
        log.debug(f"测试过程异常: {e}")
        return None
        
    finally:
        # 清理进程
        try:
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
            except:
                pass
        
        # 删除临时配置文件
        try:
            os.remove(cfg_path)
        except:
            pass

# ==========================
# 主流程
# ==========================

def main():
    # 检查 Xray 二进制文件是否存在
    if not os.path.exists(XRAY_BIN):
        log.error(f"Xray 二进制文件不存在: {XRAY_BIN}")
        log.error("请确保已通过 GitHub Actions 下载 Xray")
        return
    
    # 检查订阅文件是否存在
    if not os.path.exists("sub.txt"):
        log.error("订阅文件 sub.txt 不存在")
        return

    # 读取并处理订阅内容
    try:
        with open("sub.txt", "r", encoding="utf-8") as f:
            content = f.read()
        
        lines = decode_subscription(content)
        log.info(f"解析到 {len(lines)} 个节点")
        
    except Exception as e:
        log.error(f"读取订阅文件失败: {e}")
        return

    ok_nodes = []
    tested_count = 0

    for idx, line in enumerate(lines):
        if not line or len(line) < 10:  # 跳过过短的行
            continue
            
        node = parse_node(line)
        if not node:
            log.debug(f"无法解析节点: {line[:50]}...")
            continue

        tested_count += 1
        result = test_single_node(idx, line, node)
        if result:
            ok_nodes.append(result)
            
        # 短暂延迟，避免过于频繁
        time.sleep(0.5)

    # 保存可用节点
    with open("ping.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ok_nodes))

    # 清理工作目录
    try:
        shutil.rmtree(WORKDIR, ignore_errors=True)
    except:
        pass

    log.info(f"测试完成: 共测试 {tested_count} 个节点，可用 {len(ok_nodes)} 个")

if __name__ == "__main__":
    main()
