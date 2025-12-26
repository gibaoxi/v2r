#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xray 节点可用性测试（并发版）
支持批量并发测试节点
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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# 并发测试配置
CONCURRENT_TESTS = 3  # 同时测试的节点数量，可根据需要调整

HTTP_TEST_URLS = [
    "http://www.google.com/generate_204",
    "http://www.apple.com/library/test/success.html",
    "http://connectivitycheck.android.com/generate_204",
    "http://www.baidu.com/favicon.ico","http://www.163.com/favicon.ico"
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
                
                return {
                    "type": "vless",
                    "server": u.hostname,
                    "port": u.port or 443,
                    "uuid": u.username,
                    "security": q.get("security", [""])[0],
                    "sni": q.get("sni", [""])[0] or u.hostname,
                    "public_key": q.get("pbk", [""])[0],
                    "short_id": q.get("sid", [""])[0],
                    "flow": q.get("flow", [""])[0],
                    "fp": q.get("fp", [""])[0],
                    "type_param": q.get("type", ["tcp"])[0],
                    "packetEncoding": q.get("packetEncoding", [""])[0],
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
                # 简化 SS 解析
                if "#" in line:
                    line = line.split("#")[0]
                
                if "@" in line:
                    # 处理标准格式
                    parts = line.split("@")
                    user_info = parts[0][5:]  # 去掉 ss://
                    server_port = parts[1]
                    
                    if ":" in user_info:
                        method, password = user_info.split(":", 1)
                    else:
                        user_decoded = base64.b64decode(user_info + "==").decode()
                        method, password = user_decoded.split(":", 1)
                    
                    server, port = server_port.split(":", 1)
                    port = int(port)
                    
                    return {
                        "type": "shadowsocks",
                        "server": server,
                        "port": port,
                        "method": method,
                        "password": password
                    }
                else:
                    return None
                    
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
    构造正确的测试配置（简化版）
    """
    return {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False
            },
            "tag": "socks-in"
        }],
        "outbounds": [
            build_correct_outbound(node),
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "outboundTag": "proxy"
            }]
        }
    }

def build_correct_outbound(n: dict) -> dict:
    """
    构建正确的出站配置，修复 VLESS Reality 问题
    """
    if n["type"] == "vmess":
        return build_vmess_outbound(n)
    elif n["type"] == "vless":
        return build_vless_outbound(n)
    elif n["type"] == "trojan":
        return build_trojan_outbound(n)
    elif n["type"] == "shadowsocks":
        return build_ss_outbound(n)
    else:
        raise ValueError(f"不支持的节点类型: {n['type']}")

def build_vmess_outbound(n: dict) -> dict:
    """构建 VMess 出站配置"""
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

def build_vless_outbound(n: dict) -> dict:
    """构建 VLESS 出站配置，修复 Reality 问题"""
    # 基础配置
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
            "network": n.get("type_param", "tcp")
        }
    }
    
    # 处理 packetEncoding
    if n.get("packetEncoding"):
        outbound["streamSettings"]["packetEncoding"] = n["packetEncoding"]
    
    security = n.get("security", "")
    
    if security == "reality":
        # Reality 协议配置
        outbound["streamSettings"]["security"] = "reality"
        outbound["streamSettings"]["realitySettings"] = {
            "show": False,
            "fingerprint": n.get("fp", "chrome"),
            "serverName": n.get("sni", n["server"]),
            "publicKey": n.get("public_key", ""),
            "shortId": n.get("short_id", ""),
            "spiderX": "/"
        }
        
    elif security == "tls":
        # 普通 TLS 配置
        outbound["streamSettings"]["security"] = "tls"
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": n.get("sni", n["server"]),
            "fingerprint": n.get("fp", "chrome")
        }
    
    return outbound

def build_trojan_outbound(n: dict) -> dict:
    """构建 Trojan 出站配置"""
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

def build_ss_outbound(n: dict) -> dict:
    """构建 Shadowsocks 出站配置"""
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

# ==========================
# 测试函数
# ==========================

def tcp_test_twice(host: str, port: int) -> bool:
    """
    TCP 连接测试
    """
    for i in range(2):
        try:
            s = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
            s.close()
            return True
        except Exception as e:
            if i == 0:
                time.sleep(TCP_INTERVAL)
    
    return False

def http_test_simple(socks_port: int) -> bool:
    """
    简单的 HTTP 测试
    """
    proxies = {
        "http": f"socks5://127.0.0.1:{socks_port}",
        "https": f"socks5://127.0.0.1:{socks_port}",
    }
    
    # 先测试代理端口是否监听
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=2)
        s.close()
    except:
        return False
    
    test_urls = random.sample(HTTP_TEST_URLS, min(2, len(HTTP_TEST_URLS)))
    
    for url in test_urls:
        try:
            response = requests.get(
                url,
                proxies=proxies,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                stream=True
            )
            response.close()
            
            if response.status_code in (200, 204, 301, 302):
                return True
                
        except Exception:
            continue
    
    return False

# ==========================
# 订阅文件处理
# ==========================

def decode_subscription(content: str) -> list:
    """
    处理订阅内容
    """
    lines = []
    
    # 先尝试 base64 解码
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    except:
        # 如果不是 base64，直接按行处理
        lines = [line.strip() for line in content.splitlines() if line.strip()]
    
    return lines

# ==========================
# 单节点测试流程
# ==========================

def test_single_node(args):
    """
    测试单个节点 - 修改为接收参数元组，便于线程池使用
    """
    index, line, node = args
    socks_port = SOCKS_PORT_BASE + index
    cfg_path = f"{WORKDIR}/config_{index}.json"
    
    log.info(f"测试节点 {index+1}: {node['server']}:{node['port']} ({node['type']})")

    process = None
    try:
        # 生成配置
        config = build_xray_config(node, socks_port)
        
        # 保存配置
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        # 启动 Xray
        process = subprocess.Popen(
            [XRAY_BIN, "run", "-config", cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待启动
        time.sleep(XRAY_BOOT_WAIT)
        
        # 检查进程状态
        if process.poll() is not None:
            return None
        
        # TCP 测试
        if not tcp_test_twice(node["server"], node["port"]):
            return None
        
        # HTTP 测试
        if not http_test_simple(socks_port):
            return None
        
        log.info(f"✅ 可用节点: {node['server']}")
        return line
        
    except Exception as e:
        return None
        
    finally:
        # 清理
        if process:
            try:
                process.terminate()
                process.wait(timeout=2)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        try:
            os.remove(cfg_path)
        except:
            pass

# ==========================
# 批量测试函数
# ==========================

def batch_test_nodes(node_list, concurrent_tests=CONCURRENT_TESTS):
    """
    批量测试节点，支持并发
    """
    ok_nodes = []
    total_nodes = len(node_list)
    
    log.info(f"开始批量测试 {total_nodes} 个节点，并发数: {concurrent_tests}")
    
    with ThreadPoolExecutor(max_workers=concurrent_tests) as executor:
        # 提交所有测试任务
        future_to_node = {
            executor.submit(test_single_node, (idx, line, node)): (idx, line, node) 
            for idx, (line, node) in enumerate(node_list)
        }
        
        # 处理完成的任务
        completed = 0
        for future in as_completed(future_to_node):
            idx, line, node = future_to_node[future]
            completed += 1
            
            try:
                result = future.result()
                if result:
                    ok_nodes.append(result)
            except Exception as e:
                log.debug(f"节点测试异常: {e}")
            
            # 进度显示
            if completed % 10 == 0 or completed == total_nodes:
                log.info(f"测试进度: {completed}/{total_nodes}，已发现 {len(ok_nodes)} 个可用节点")
    
    return ok_nodes

# ==========================
# 主流程
# ==========================

def main():
    # 检查文件
    if not os.path.exists(XRAY_BIN):
        log.error(f"Xray 不存在: {XRAY_BIN}")
        return
    
    if not os.path.exists("sub.txt"):
        log.error("订阅文件不存在")
        return
    
    # 读取订阅
    try:
        with open("sub.txt", "r", encoding="utf-8") as f:
            content = f.read()
        
        lines = decode_subscription(content)
        log.info(f"找到 {len(lines)} 个节点")
        
    except Exception as e:
        log.error(f"读取订阅失败: {e}")
        return
    
    # 解析节点
    valid_nodes = []
    for line in lines:
        if not line.strip():
            continue
            
        node = parse_node(line)
        if node:
            valid_nodes.append((line, node))
    
    log.info(f"成功解析 {len(valid_nodes)} 个有效节点")
    
    if not valid_nodes:
        log.error("没有找到有效节点")
        return
    
    # 批量测试节点
    ok_nodes = batch_test_nodes(valid_nodes, CONCURRENT_TESTS)
    
    # 保存结果
    with open("ping.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ok_nodes))
    
    # 清理
    try:
        shutil.rmtree(WORKDIR, ignore_errors=True)
    except:
        pass
    
    log.info(f"测试完成: {len(valid_nodes)} 个节点中 {len(ok_nodes)} 个可用")
    
    # 显示可用节点信息
    if ok_nodes:
        log.info("可用节点列表:")
        for i, node_line in enumerate(ok_nodes, 1):
            node = parse_node(node_line)
            if node:
                log.info(f"  {i}. {node['server']}:{node['port']} ({node['type']})")

# ==========================
# 命令行参数支持
# ==========================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Xray 节点批量测试工具')
    parser.add_argument('-c', '--concurrent', type=int, default=CONCURRENT_TESTS, 
                       help=f'并发测试数量 (默认: {CONCURRENT_TESTS})')
    parser.add_argument('-t', '--timeout', type=int, default=HTTP_TIMEOUT,
                       help=f'HTTP 测试超时时间 (默认: {HTTP_TIMEOUT})')
    parser.add_argument('-f', '--file', default='sub.txt',
                       help='订阅文件路径 (默认: all_configs.txt)')
    
    args = parser.parse_args()
    
    # 更新配置
    CONCURRENT_TESTS = args.concurrent
    HTTP_TIMEOUT = args.timeout
    
    if args.file != 'all_configs.txt':
        # 如果指定了不同的文件，复制到 sub.txt
        if os.path.exists(args.file):
            shutil.copy(args.file, 'all_configs.txt')
            log.info(f"使用订阅文件: {args.file}")
    
    log.info(f"并发测试数: {CONCURRENT_TESTS}, HTTP超时: {HTTP_TIMEOUT}秒")
    
    main()
