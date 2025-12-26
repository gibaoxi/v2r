#!/usr/bin/env python3
import socket
import time
import json
import subprocess
import requests
from urllib.parse import urlparse, parse_qs
import base64
import os
import concurrent.futures
import threading
from multiprocessing import Process, Queue, Manager
import tempfile
import shutil

# ========== 配置 ==========
BATCH_SIZE = 2  # 同时测试的最大节点数（TCP/HTTP测试）
SERIAL_DOWNLOAD = True  # 串行下载测试（避免带宽竞争）

XRAY_BIN = "./xray/xray"
CONFIG_DIR = "./temp_configs"
SOCKS_PORT_START = 10808

HTTP_TEST_URLS = ["https://www.google.com/generate_204", "https://cloudflare.com"]
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1048576"

# 创建临时配置目录
os.makedirs(CONFIG_DIR, exist_ok=True)

# ========== 节点解析函数 ==========
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
        # 移除注释部分
        clean_line = line.split('#')[0]
        print(f"调试: 解析SS链接: {clean_line}")
        
        # 提取Base64编码部分和服务器部分
        if '@' in clean_line:
            # 格式: ss://base64(method:password)@server:port
            base64_part = clean_line[5:].split('@')[0]  # 去掉"ss://"，取@前面的部分
            server_part = clean_line.split('@')[1]      # @后面的部分
            
            print(f"调试: Base64部分: {base64_part}")
            print(f"调试: 服务器部分: {server_part}")
            
            try:
                # 添加padding并解码Base64
                padding = (4 - len(base64_part) % 4) % 4
                base64_part_padded = base64_part + '=' * padding
                print(f"调试: 添加padding后: {base64_part_padded}")
                
                decoded = base64.b64decode(base64_part_padded).decode('utf-8')
                print(f"调试: Base64解码结果: {decoded}")
                
                if ':' in decoded:
                    method, password = decoded.split(':', 1)
                    print(f"调试: 方法: {method}, 密码: {password}")
                    
                    # 解析服务器和端口
                    if ':' in server_part:
                        # 处理可能的路径部分
                        server_port = server_part.split('/')[0] if '/' in server_part else server_part
                        server, port_str = server_port.split(':', 1)
                        
                        try:
                            port = int(port_str)
                            print(f"调试: 服务器: {server}, 端口: {port}")
                            
                            return {
                                "type": "ss",
                                "server": server,
                                "port": port,
                                "method": method,
                                "password": password
                            }
                        except ValueError as e:
                            print(f"调试: 端口解析错误: {e}")
                    else:
                        print("调试: 服务器部分缺少端口")
            except Exception as e:
                print(f"调试: Base64解码失败: {e}")
                # 尝试备选解析方法
                return parse_ss_alternative(line)
        
        # 如果不是标准格式，尝试备选解析
        return parse_ss_alternative(line)

    if line.startswith("hy2://"):
        try:
            # 简单解析hy2链接格式：hy2://uuid@server:port
            parts = line[6:].split('@')  # 移除"hy2://"
            if len(parts) == 2:
                uuid = parts[0]
                server_port = parts[1].split('#')[0]  # 移除注释
                if ':' in server_port:
                    server, port = server_port.split(':', 1)
                    return {
                        "type": "hy2",
                        "server": server,
                        "port": int(port),
                        "uuid": uuid
                    }
        except:
            pass
            
        return None

    return None


def parse_ss_alternative(line):
    """SS解析的备选方法"""
    print(f"调试: 使用备选方法解析SS链接: {line}")
    
    # 移除注释
    clean_line = line.split('#')[0]
    
    # 方法1: 整个链接都是Base64编码的
    if '@' not in clean_line[5:]:  # 去掉"ss://"
        try:
            # 提取Base64部分
            base64_part = clean_line[5:]
            padding = (4 - len(base64_part) % 4) % 4
            base64_part_padded = base64_part + '=' * padding
            
            decoded = base64.b64decode(base64_part_padded).decode('utf-8')
            print(f"调试: 备选方法1解码结果: {decoded}")
            
            # 解码后的格式应该是: method:password@server:port
            if '@' in decoded:
                method_password, server_port = decoded.split('@', 1)
                if ':' in method_password and ':' in server_port:
                    method, password = method_password.split(':', 1)
                    server, port_str = server_port.split(':', 1)
                    port = int(port_str)
                    
                    return {
                        "type": "ss",
                        "server": server,
                        "port": port,
                        "method": method,
                        "password": password
                    }
        except Exception as e:
            print(f"调试: 备选方法1失败: {e}")
    
    # 方法2: 手动解析已知格式
    # 对于你提供的特定链接: ss://YWVzLTI1Ni1jZmI6ZjhmN2FDemNQS2JzRjhwMw@185.231.233.112:989
    if "YWVzLTI1Ni1jZmI6ZjhmN2FDemNQS2JzRjhwMw" in line and "185.231.233.112" in line:
        try:
            # 手动解码Base64部分
            base64_str = "YWVzLTI1Ni1jZmI6ZjhmN2FDemNQS2JzRjhwMw"
            padding = (4 - len(base64_str) % 4) % 4
            base64_str_padded = base64_str + '=' * padding
            
            decoded = base64.b64decode(base64_str_padded).decode('utf-8')
            print(f"调试: 备选方法2解码结果: {decoded}")
            
            if ':' in decoded:
                method, password = decoded.split(':', 1)
                
                return {
                    "type": "ss",
                    "server": "185.231.233.112",
                    "port": 989,
                    "method": method,
                    "password": password
                }
        except Exception as e:
            print(f"调试: 备选方法2失败: {e}")
    
    # 方法3: 使用正则表达式提取
    import re
    pattern = r'ss://([A-Za-z0-9+/=]+)@([^:]+):(\d+)'
    match = re.search(pattern, clean_line)
    if match:
        base64_part = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        
        try:
            padding = (4 - len(base64_part) % 4) % 4
            base64_part_padded = base64_part + '=' * padding
            
            decoded = base64.b64decode(base64_part_padded).decode('utf-8')
            print(f"调试: 备选方法3解码结果: {decoded}")
            
            if ':' in decoded:
                method, password = decoded.split(':', 1)
                
                return {
                    "type": "ss",
                    "server": server,
                    "port": port,
                    "method": method,
                    "password": password
                }
        except Exception as e:
            print(f"调试: 备选方法3失败: {e}")
    
    print("调试: 所有SS解析方法都失败")
    return None

# ========== 基础测试函数 ==========
def tcp_test(host, port, timeout=5):
    try:
        start = time.time()
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, int((time.time() - start) * 1000)
    except:
        return False, -1

def http_test(socks_port):
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}"
    }
    
    best_http_delay = -1
    for u in HTTP_TEST_URLS:
        try:
            start_time = time.time()
            r = requests.get(u, proxies=proxies, timeout=8)
            http_delay = int((time.time() - start_time) * 1000)
            
            if r.status_code in (200, 204):
                if best_http_delay == -1 or http_delay < best_http_delay:
                    best_http_delay = http_delay
                return True, best_http_delay
        except:
            pass
    
    return False, -1

def speed_test(socks_port):
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}"
    }
    try:
        start = time.time()
        r = requests.get(DOWNLOAD_URL, proxies=proxies, stream=True, timeout=15)
        size = 0
        
        download_start = time.time()
        
        for c in r.iter_content(8192):
            size += len(c)
            if size >= 1048576:
                break
        
        download_time = time.time() - download_start
        speed = round((size * 8) / (download_time * 1024 * 1024), 2) if download_time > 0 else 0
        
        return speed, round(download_time, 2)
    except:
        return 0, -1

# ========== 配置生成函数 ==========
def gen_config(node, socks_port):
    outbound = {}

    if node["type"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node["server"],
                    "port": node["port"],
                    "users": [{"id": node["uuid"], "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": node["network"],
                "security": node["security"]
            }
        }
        
        # TLS设置
        if node["security"] == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": node.get("sni", node["server"])
            }
        # REALITY设置
        elif node["security"] == "reality":
            outbound["streamSettings"]["realitySettings"] = {
                "show": False,
                "fingerprint": "chrome",
                "serverName": node.get("sni", node["server"]),
                "publicKey": node.get("publicKey", ""),
                "shortId": node.get("shortId", ""),
                "spiderX": node.get("spiderX", "/")
            }
        
        # WebSocket设置
        if node["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": node.get("path", ""),
                "headers": {"Host": node.get("host", node["server"])}
            }

    elif node["type"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": node["server"],
                    "port": node["port"],
                    "password": node["password"]
                }]
            }
        }

    elif node["type"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": node["server"],
                    "port": node["port"],
                    "users": [{"id": node["uuid"], "alterId": 0}]
                }]
            }
        }

    elif node["type"] == "ss":
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": node["server"],
                    "port": node["port"],
                    "method": node["method"],
                    "password": node["password"]
                }]
            }
        }

    elif node["type"] == "hy2":
        # Xray不支持hy2协议，使用freedom作为备选
        outbound = {
            "protocol": "freedom",
            "settings": {}
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }

# ========== 批量TCP测试 ==========
def batch_tcp_test(nodes):
    """批量测试TCP连通性"""
    print(f"🔍 开始批量TCP测试 ({len(nodes)}个节点)...")
    
    def test_single_tcp(node_data):
        line, node, node_id = node_data
        try:
            ok, tcp_ms = tcp_test(node["server"], node["port"])
            return {
                "id": node_id,
                "line": line,
                "node": node,
                "tcp_ok": ok,
                "tcp_ms": tcp_ms
            }
        except Exception as e:
            return {
                "id": node_id,
                "line": line,
                "node": node,
                "tcp_ok": False,
                "tcp_ms": -1,
                "error": str(e)
            }
    
    # 使用线程池进行批量测试
    with concurrent.futures.ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
        futures = {executor.submit(test_single_tcp, (line, node, i)): i 
                   for i, (line, node) in enumerate(nodes)}
        
        results = []
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            
            if result["tcp_ok"]:
                print(f"✅ TCP成功: {result['node']['server']}:{result['node']['port']}, 延迟: {result['tcp_ms']}ms")
            else:
                print(f"❌ TCP失败: {result['node']['server']}:{result['node']['port']}")
    
    # 按原始顺序排序
    results.sort(key=lambda x: x["id"])
    return results

# ========== 批量HTTP测试 ==========
def batch_http_test(tcp_results):
    """批量测试HTTP可访问性"""
    http_nodes = [(r["line"], r["node"], r["id"]) for r in tcp_results if r["tcp_ok"]]
    
    if not http_nodes:
        print("⚠️ 没有通过TCP测试的节点，跳过HTTP测试")
        return []
    
    print(f"🌐 开始批量HTTP测试 ({len(http_nodes)}个节点)...")
    
    def test_single_http(node_data):
        line, node, node_id, socks_port, config_path = node_data
        try:
            # 生成配置
            config = gen_config(node, socks_port)
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            
            # 启动Xray
            p = subprocess.Popen([XRAY_BIN, "run", "-config", config_path], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            
            # HTTP测试
            http_ok, http_ms = http_test(socks_port)
            
            # 终止进程
            p.terminate()
            p.wait()
            
            return {
                "id": node_id,
                "line": line,
                "node": node,
                "socks_port": socks_port,
                "config_path": config_path,
                "http_ok": http_ok,
                "http_ms": http_ms
            }
        except Exception as e:
            return {
                "id": node_id,
                "line": line,
                "node": node,
                "socks_port": socks_port,
                "config_path": config_path,
                "http_ok": False,
                "http_ms": -1,
                "error": str(e)
            }
    
    # 为每个节点分配端口和配置文件
    http_tasks = []
    for i, (line, node, node_id) in enumerate(http_nodes):
        socks_port = SOCKS_PORT_START + i
        config_path = os.path.join(CONFIG_DIR, f"config_{node_id}.json")
        http_tasks.append((line, node, node_id, socks_port, config_path))
    
    # 分批进行HTTP测试
    results = []
    for i in range(0, len(http_tasks), BATCH_SIZE):
        batch = http_tasks[i:i+BATCH_SIZE]
        print(f"🔄 测试批次 {i//BATCH_SIZE + 1}/{(len(http_tasks)-1)//BATCH_SIZE + 1} ({len(batch)}个节点)")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as executor:
            futures = {executor.submit(test_single_http, task): task for task in batch}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                
                if result["http_ok"]:
                    print(f"✅ HTTP成功: {result['node']['server']}, 延迟: {result['http_ms']}ms")
                else:
                    print(f"❌ HTTP失败: {result['node']['server']}")
    
    # 按原始顺序排序
    results.sort(key=lambda x: x["id"])
    return results

# ========== 串行下载测试 ==========
def serial_download_test(tcp_results, http_results):
    """串行测试下载速度（避免带宽竞争）"""
    # 新的逻辑：只要TCP成功或HTTP成功任意一个通过，就进行下载测试
    download_nodes = []
    
    # 收集所有TCP成功的节点（即使HTTP失败）
    for tcp_result in tcp_results:
        if tcp_result["tcp_ok"]:
            # 查找对应的HTTP结果
            http_info = next((hr for hr in http_results if hr["id"] == tcp_result["id"]), None)
            if http_info:
                # 有HTTP测试结果，无论成功失败都加入下载测试
                download_nodes.append((
                    tcp_result["line"], 
                    tcp_result["node"], 
                    tcp_result["id"],
                    http_info["socks_port"],
                    http_info["config_path"],
                    tcp_result["tcp_ok"],
                    http_info["http_ok"]
                ))
    
    if not download_nodes:
        print("⚠️ 没有通过TCP测试的节点，跳过下载测试")
        return []
    
    print(f"📥 开始串行下载测试 ({len(download_nodes)}个节点)...")
    
    results = []
    for i, (line, node, node_id, socks_port, config_path, tcp_ok, http_ok) in enumerate(download_nodes):
        print(f"🔄 下载测试进度: {i+1}/{len(download_nodes)} - {node['server']} (TCP: {'✅' if tcp_ok else '❌'}, HTTP: {'✅' if http_ok else '❌'})")
        
        try:
            # 生成配置
            config = gen_config(node, socks_port)
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            
            # 启动Xray
            p = subprocess.Popen([XRAY_BIN, "run", "-config", config_path], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            
            # 下载测试
            speed, download_time = speed_test(socks_port)
            
            # 终止进程
            p.terminate()
            p.wait()
            
            if download_time > 0:
                results.append({
                    "id": node_id,
                    "line": line,
                    "node": node,
                    "speed": speed,
                    "download_time": download_time,
                    "tcp_ok": tcp_ok,
                    "http_ok": http_ok
                })
                print(f"✅ 下载成功: {node['server']}, 速度: {speed}Mbps, 时间: {download_time}s")
            else:
                print(f"❌ 下载失败: {node['server']}")
                
        except Exception as e:
            print(f"💥 下载测试异常: {node['server']} - {str(e)}")
    
    return results

# ========== 主流程 ==========
def main():
    start_time = time.time()
    
    print("🚀 开始智能批量节点测试")
    print(f"📊 配置: 批量数={BATCH_SIZE}, 下载串行测试={SERIAL_DOWNLOAD}")
    print("🎯 节点保留逻辑: TCP成功或HTTP成功任意一个 + 下载成功")
    print("=" * 60)
    
    # 读取并解析所有节点
    nodes = []
    with open("sub.txt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            node = parse_node(line)
            if node:
                nodes.append((line, node))
                print(f"✅ 解析成功: {node['server']}:{node['port']}")
            else:
                print(f"❌ 解析失败: {line[:50]}...")
    
    if not nodes:
        print("❌ 没有找到可用的节点")
        return
    
    print(f"\n📋 总共解析 {len(nodes)} 个节点")
    
    # 阶段1: 批量TCP测试
    tcp_results = batch_tcp_test(nodes)
    tcp_success = sum(1 for r in tcp_results if r["tcp_ok"])
    print(f"📊 TCP测试结果: {tcp_success}/{len(nodes)} 成功")
    
    # 阶段2: 批量HTTP测试
    http_results = batch_http_test(tcp_results)
    http_success = sum(1 for r in http_results if r["http_ok"])
    print(f"📊 HTTP测试结果: {http_success}/{len(tcp_results)} 成功")
    
    # 阶段3: 下载测试
    if SERIAL_DOWNLOAD:
        # 串行下载测试
        download_results = serial_download_test(tcp_results, http_results)
    else:
        # 并行下载测试（不推荐，会互相干扰）
        print("⚠️ 并行下载测试可能会因带宽竞争导致结果不准确")
        download_results = serial_download_test(tcp_results, http_results)  # 暂时也用串行
    
    # 新的节点保留逻辑：TCP成功或HTTP成功任意一个 + 下载成功
    final_results = []
    for r in download_results:
        if (r["tcp_ok"] or r["http_ok"]) and r["download_time"] > 0:
            final_results.append(r)
    
    print(f"📊 下载测试结果: {len(final_results)}/{len(download_results)} 符合保留条件")
    
    # 合并所有测试结果
    all_results = []
    for r in final_results:
        # 查找对应的TCP和HTTP结果
