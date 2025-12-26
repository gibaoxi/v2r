#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xray 节点可用性测试（完整修复版）
专门修复 VLESS Reality 协议问题
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
HTTP_TIMEOUT = 10

TCP_INTERVAL = 0.6
XRAY_BOOT_WAIT = 3.0

HTTP_TEST_URLS = [
    "http://www.google.com/generate_204",
    "http://www.apple.com/library/test/success.html",
    "http://connectivitycheck.android.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
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
# 节点解析 - 修复 Reality 参数解析
# ==========================

def parse_node(line: str):
    """
    解析 sub.txt 中的节点，特别修复 Reality 协议解析
    """
    try:
        if line.startswith("vmess://"):
            try:
                raw = base64.b64decode(line[8:] + "==").decode()
                j = json.loads(raw)
                return {
                    "type": "vmess",
                    "server": j["add"],
                    "port": int(j["port"]),
                    "uuid": j["id"],
                    "tls": j.get("tls") == "tls"
                }
            except Exception as e:
                log.debug(f"VMess 解析失败: {e}")
                return None

        if line.startswith("vless://"):
            try:
                u = urlparse(line)
                q = parse_qs(u.query)
                
                # 调试输出解析的参数
                log.debug(f"VLESS 参数: {dict(q)}")
                
                return {
                    "type": "vless",
                    "server": u.hostname,
                    "port": u.port or 443,
                    "uuid": u.username,
                    "security": q.get("security", [""])[0],
                    "sni": q.get("sni", [""])[0] or u.hostname,  # 修复 sni 获取
                    "public_key": q.get("pbk", [""])[0],
                    "short_id": q.get("sid", [""])[0],
                    "flow": q.get("flow", [""])[0],
                    "fp": q.get("fp", [""])[0],
                    "type_param": q.get("type", ["tcp"])[0],
                    "packetEncoding": q.get("packetEncoding", [""])[0],
                    "encryption": q.get("encryption", ["none"])[0],
                    "host": q.get("host", [""])[0],
                    "path": q.get("path", [""])[0],
                }
            except Exception as e:
                log.debug(f"VLESS 解析失败: {e}")
                return None

        if line.startswith("trojan://"):
            try:
                u = urlparse(line)
                q = parse_qs(u.query)
                return {
                    "type": "trojan",
                    "server": u.hostname,
                    "port": u.port or 443,
                    "password": u.username,
                    "sni": q.get("sni", [u.hostname])[0]
                }
            except Exception as e:
                log.debug(f"Trojan 解析失败: {e}")
                return None
            
        if line.startswith("ss://"):
            try:
                ss_part = line[5:]
                if "#" in ss_part:
                    ss_part = ss_part.split("#")[0]
                
                if "@" not in ss_part and ":" not in ss_part:
                    decoded = base64.b64decode(ss_part + "==").decode('utf-8')
                    if "@" in decoded:
                        method_password, server_port = decoded.split("@", 1)
                        method, password = method_password.split(":", 1)
                        server, port = server_port.split(":", 1)
                    else:
                        parts = decoded.split(":")
                        if len(parts) >= 3:
                            method = parts[0]
                            password = parts[1]
                            server = parts[2]
                            port = parts[3] if len(parts) > 3 else "8388"
                        else:
                            return None
                else:
                    if "@" in ss_part:
                        user_info, server_port = ss_part.split("@", 1)
                        if ":" in user_info:
                            method, password = user_info.split(":", 1)
                        else:
                            user_info_decoded = base64.b64decode(user_info + "==").decode('utf-8')
                            method, password = user_info_decoded.split(":", 1)
                        
                        server, port = server_port.split(":", 1)
                    else:
                        parts = ss_part.split(":")
                        if len(parts) >= 3:
                            method = parts[0]
                            password = parts[1]
                            server = parts[2]
                            port = parts[3] if len(parts) > 3 else "8388"
                        else:
                            return None
                
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
# Xray 配置生成 - 修复 Reality 配置
# ==========================

def build_xray_config(node: dict, socks_port: int) -> dict:
    """
    构造最小可用 Xray 配置
    """
    inbound_tag = "socks-in"
    
    config = {
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [{
            "tag": inbound_tag,
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
                "inboundTag": [inbound_tag],
                "outboundTag": "proxy"
            }]
        }
    }
    
    return config

def build_outbound(n: dict) -> dict:
    """
    根据节点类型生成 outbound，特别修复 Reality 配置
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
        
        if n.get("tls"):
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": n["server"]
            }
            
        return outbound

    elif n["type"] == "vless":
        # 构建基础配置
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": n["server"],
                    "port": n["port"],
                    "users": [{
                        "id": n["uuid"],
                        "encryption": n.get("encryption", "none"),
                        "flow": n.get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": n.get("type_param", "tcp")
            }
        }

        # 处理 packetEncoding
        if n.get("packetEncoding"):
            outbound["streamSettings"]["packetEncoding"] = n["packetEncoding"]

        security = n.get("security", "")
        log.debug(f"构建 VLESS 配置，安全协议: {security}")
        
        if security in ("tls", "reality"):
            outbound["streamSettings"]["security"] = security
            
            # TLS 基础设置
            tls_settings = {
                "serverName": n.get("sni", n["server"])
            }
            
            # 添加指纹
            if n.get("fp"):
                tls_settings["fingerprint"] = n["fp"]
                
            outbound["streamSettings"]["tlsSettings"] = tls_settings
            
            # Reality 特殊设置
            if security == "reality":
                reality_settings = {
                    "show": False,
                    "fingerprint": n.get("fp", "firefox"),  # 默认使用 firefox
                    "serverName": n.get("sni", n["server"]),
                    "publicKey": n.get("public_key", ""),
                    "shortId": n.get("short_id", ""),
                    "spiderX": "/"
                }
                
                # 只有存在公钥时才添加 realitySettings
                if n.get("public_key"):
                    outbound["streamSettings"]["realitySettings"] = reality_settings
                    log.debug(f"Reality 配置: publicKey={n.get('public_key')}, shortId={n.get('short_id')}")
                else:
                    log.warning("Reality 节点缺少公钥配置")

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
                    "password": n["password"],
                    "ota": False
                }]
            }
        }

    raise ValueError(f"不支持的节点类型: {n['type']}")

# ==========================
# 测试函数
# ==========================

def tcp_test_twice(host: str, port: int) -> bool:
    """
    对节点做两次 TCP connect，任意一次成功即可
    """
    for i in range(2):
        try:
            s = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
            s.close()
            log.debug(f"TCP 第 {i+1} 次成功: {host}:{port}")
            return True
        except Exception as e:
            log.debug(f"TCP 第 {i+1} 次失败 {host}:{port} - {e}")
            if i == 0:
                time.sleep(TCP_INTERVAL)
    
    return False

def http_test_with_retry(socks_port: int, max_retries: int = 2) -> bool:
    """
    HTTP 测试，增加重试机制
    """
    test_urls = random.sample(HTTP_TEST_URLS, min(2, len(HTTP_TEST_URLS)))
    proxies = {
        "http": f"socks5://127.0.0.1:{socks_port}",
        "https": f"socks5://127.0.0.1:{socks_port}",
    }
    
    for url in test_urls:
        for retry in range(max_retries):
            try:
                log.debug(f"HTTP 测试尝试 {retry+1}: {url}")
                
                # 先测试代理端口是否可用
                try:
                    s = socket.create_connection(("127.0.0.1", socks_port), timeout=2)
                    s.close()
                except:
                    log.debug(f"代理端口 {socks_port} 不可用")
                    return False
                
                r = requests.get(
                    url,
                    proxies=proxies,
                    timeout=HTTP_TIMEOUT,
                    allow_redirects=True,
                    stream=True
                )
                r.close()
                
                log.debug(f"HTTP 状态码: {r.status_code}")
                
                if r.status_code in (200, 204, 301, 302):
                    log.debug(f"HTTP 测试成功: {url}")
                    return True
                    
            except requests.exceptions.ProxyError as e:
                log.debug(f"代理错误 {url} (尝试 {retry+1}): {e}")
            except requests.exceptions.ConnectTimeout as e:
                log.debug(f"连接超时 {url} (尝试 {retry+1}): {e}")
            except requests.exceptions.ReadTimeout as e:
                log.debug(f"读取超时 {url} (尝试 {retry+1}): {e}")
            except requests.exceptions.ConnectionError as e:
                log.debug(f"连接错误 {url} (尝试 {retry+1}): {e}")
            except Exception as e:
                log.debug(f"其他错误 {url} (尝试 {retry+1}): {e}")
            
            if retry < max_retries - 1:
                time.sleep(1)  # 重试前等待

    return False

# ==========================
# 订阅文件处理
# ==========================

def decode_subscription(content: str) -> list:
    """
    处理订阅内容，可能是 base64 编码的
    """
    lines = []
    
    direct_lines = [line.strip() for line in content.splitlines() if line.strip()]
    
    has_protocol = any(line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://')) 
                      for line in direct_lines)
    
    if has_protocol:
        return direct_lines
    
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        return decoded_lines
    except:
        pass
    
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

    process = None
    try:
        # 生成 Xray 配置
        config = build_xray_config(node, socks_port)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        log.debug(f"Xray 配置文件已生成: {cfg_path}")
        
        # 保存配置文件用于调试
        debug_cfg_path = f"{WORKDIR}/debug_config_{index}.json"
        with open(debug_cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        # 启动 Xray
        process = subprocess.Popen(
            [XRAY_BIN, "run", "-config", cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(XRAY_BOOT_WAIT)

        # 检查进程是否正常运行
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            log.error(f"Xray 启动失败: {stderr.decode()}")
            return None

        # 执行测试
        if not tcp_test_twice(node["server"], node["port"]):
            log.info(f"❌ TCP 连接失败: {node['server']}")
            return None

        if not http_test_with_retry(socks_port):
            log.info(f"❌ HTTP 代理失败: {node['server']}")
            return None

        log.info(f"✅ 可用节点: {node['server']}")
        return line

    except Exception as e:
        log.error(f"测试过程异常: {e}")
        return None
        
    finally:
        # 清理进程
        if process:
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
            os.remove(f"{WORKDIR}/debug_config_{index}.json")
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
    node_types = {}

    for idx, line in enumerate(lines):
        if not line or len(line) < 10:
            continue
            
        node = parse_node(line)
        if not node:
            log.debug(f"无法解析节点: {line[:50]}...")
            continue

        # 统计节点类型
        node_type = node["type"]
        node_types[node_type] = node_types.get(node_type, 0) + 1

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

    # 输出统计信息
    log.info(f"节点类型统计: {node_types}")
    log.info(f"测试完成: 共测试 {tested_count} 个节点，可用 {len(ok_nodes)} 个")

if __name__ == "__main__":
    main()
