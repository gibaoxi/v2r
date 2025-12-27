#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import socket
import signal
import subprocess
import threading
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

# ================== 配置常量 ==================
XRAY_BIN = "./xray/xray"
SUB_FILE = "all_configs.txt"
GOOD_FILE = "ping.txt"
BAD_FILE = "bad.txt"

MAX_WORKERS = 3
TCP_TIMEOUT = 8
HTTP_TIMEOUT = 10
SOCKS_BASE = 30000
XRAY_START_DELAY = 2

HTTP_TEST_URLS = [
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
]

lock = threading.Lock()

# ================== 初始化检查 ==================
def initialize():
    """初始化检查和环境准备"""
    if not os.path.exists(XRAY_BIN):
        raise FileNotFoundError(f"Xray 不存在: {XRAY_BIN}")
    
    if not os.access(XRAY_BIN, os.X_OK):
        os.chmod(XRAY_BIN, 0o755)
        print(f"[INFO] 已添加执行权限: {XRAY_BIN}")
    
    if not os.path.exists(SUB_FILE):
        raise FileNotFoundError(f"订阅文件不存在: {SUB_FILE}")
    
    print(f"[INFO] 环境检查通过: Xray={XRAY_BIN}, Workers={MAX_WORKERS}")

# ================== 日志工具 ==================
def log(msg, level="INFO"):
    """带颜色和时间的日志输出"""
    colors = {"INFO": "\033[94m", "WARN": "\033[93m", "ERROR": "\033[91m", "SUCCESS": "\033[92m"}
    reset = "\033[0m"
    color = colors.get(level, "\033[94m")
    print(f"{color}[{time.strftime('%H:%M:%S')}] {level}: {msg}{reset}", flush=True)

# ================== 网络测试工具 ==================
def robust_tcp_test(host, port, retries=2):
    """健壮的TCP连接测试"""
    for attempt in range(retries):
        try:
            start_time = time.time()
            with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
                latency = int((time.time() - start_time) * 1000)
                return True, f"tcp_ok({latency}ms)"
        except socket.gaierror as e:
            return False, f"DNS解析失败: {e}"
        except socket.timeout:
            if attempt == retries - 1:
                return False, "连接超时"
        except ConnectionRefusedError:
            return False, "连接被拒绝"
        except Exception as e:
            if attempt == retries - 1:
                return False, f"连接错误: {e}"
        time.sleep(0.5)
    return False, "未知错误"

def http_test_via_socks(port, test_count=2):
    """通过SOCKS代理进行HTTP测试"""
    proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    
    for _ in range(test_count):
        url = random.choice(HTTP_TEST_URLS)
        try:
            start_time = time.time()
            response = requests.get(url, proxies=proxies, timeout=HTTP_TIMEOUT, 
                                  headers={'User-Agent': 'Mozilla/5.0'})
            latency = int((time.time() - start_time) * 1000)
            
            if response.status_code in (200, 204):
                return True, latency
        except requests.exceptions.ConnectTimeout:
            continue
        except requests.exceptions.ReadTimeout:
            continue
        except Exception:
            continue
    
    return False, 0

def validate_xray_config(node):
    """验证Xray配置的完整性"""
    required_fields = {
        "ss": ["host", "port", "method", "password"],
        "vmess": ["host", "port", "uuid"],
        "vless": ["host", "port", "uuid"], 
        "trojan": ["host", "port", "password"]
    }
    
    proto = node["_type"]
    if proto not in required_fields:
        return False, f"未知协议类型: {proto}"
    
    for field in required_fields[proto]:
        if field not in node or not node[field]:
            return False, f"缺少必要字段: {field}"
    
    # 特殊验证
    if proto == "vmess" and "id" not in node and "uuid" not in node:
        return False, "VMess缺少UUID"
    
    # VMess配置冲突验证
    if proto == "vmess":
        net_type = node.get("net", node.get("type", "tcp"))
        path = node.get("path", "")
        
        # TCP协议不应有path参数
        if net_type == "tcp" and path:
            return False, "TCP协议不应包含path参数"
        
        # WebSocket协议需要path参数
        if net_type == "ws" and not path:
            return False, "WebSocket协议需要path参数"
    
    return True, "配置验证通过"

def classify_error(reason, node):
    """更精确的错误分类"""
    reason_lower = reason.lower()
    
    if "xray" in reason_lower or "配置" in reason_lower:
        config_ok, config_msg = validate_xray_config(node)
        if not config_ok:
            return f"配置错误: {config_msg}"
        return "Xray进程启动失败"
    
    elif "connection refused" in reason_lower or "连接被拒绝" in reason_lower or "errno 111" in reason_lower:
        return "服务器拒绝连接（端口可能关闭）"
    
    elif "connection timeout" in reason_lower or "连接超时" in reason_lower:
        return "连接超时（服务器无响应）"
    
    elif "http" in reason_lower and "failed" in reason_lower:
        return "HTTP代理失败（TCP通但应用层失败）"
    
    elif "dns" in reason_lower:
        return "DNS解析失败"
    
    else:
        return reason

# ================== 节点解析器（增强版） ==================
class NodeParser:
    """统一节点解析器（增强错误处理）"""
    
    @staticmethod
    def parse_ss(uri):
        """解析SS协议"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            # 处理SIP002格式
            if "@" in uri:
                parts = uri[5:].split("@", 1)
                if len(parts) != 2:
                    return None
                
                try:
                    decoded = base64.b64decode(parts[0] + "===").decode('utf-8')
                    if ":" in decoded:
                        method, password = decoded.split(":", 1)
                    else:
                        return None
                except:
                    return None
                
                server_part = parts[1]
            else:
                try:
                    decoded = base64.b64decode(uri[5:] + "===").decode('utf-8')
                    if "@" in decoded:
                        method_password, server_part = decoded.split("@", 1)
                        method, password = method_password.split(":", 1)
                    else:
                        return None
                except:
                    return None
            
            if ":" in server_part:
                host, port = server_part.rsplit(":", 1)
            else:
                return None
            
            return {
                "_type": "ss",
                "host": host.strip(),
                "port": int(port),
                "method": method.strip(),
                "password": password.strip(),
                "_raw": uri
            }
            
        except Exception as e:
            log(f"SS解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_vmess(uri):
        """解析VMess协议（增强版，自动修正配置冲突）"""
        try:
            decoded_json = base64.b64decode(uri[8:] + "===").decode('utf-8')
            config = json.loads(decoded_json)
            
            node = {
                "_type": "vmess",
                "host": config.get("add", ""),
                "port": int(config.get("port", 0)),
                "uuid": config.get("id", ""),
                "aid": int(config.get("aid", 0)),
                "_raw": uri
            }
            
            # 验证必要字段
            if not node["host"] or not node["port"] or not node["uuid"]:
                return None
            
            # 处理网络类型和路径冲突
            net_type = config.get("net", "tcp")
            path = config.get("path", "")
            
            # 自动修正：TCP协议不应该有path
            if net_type == "tcp" and path:
                log(f"⚠️ VMess配置修正: TCP协议移除非法的path参数: {path}", "WARN")
                # 设置修正后的配置
                node["net"] = net_type
                node["type"] = config.get("type", "none")
                # 不设置path字段，避免配置冲突
            else:
                # 正常设置所有字段
                optional_fields = ["net", "type", "tls", "sni", "path", "host", "alpn", "fp", "scy"]
                for field in optional_fields:
                    if field in config and config[field]:
                        node[field] = config[field]
            
            # 处理网络类型别名
            if "net" in node and not node.get("type"):
                node["type"] = node["net"]
            
            return node
            
        except Exception as e:
            log(f"VMess解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_vless(uri):
        """解析VLESS协议"""
        try:
            parsed = urlparse(uri)
            if '@' not in parsed.netloc:
                return None
                
            userinfo, hostport = parsed.netloc.split('@', 1)
            if ':' in hostport:
                host, port = hostport.rsplit(':', 1)
            else:
                host = hostport
                port = "443"
            
            query_params = parse_qs(parsed.query)
            params = {}
            for key, value in query_params.items():
                params[key] = unquote(value[0])
            
            node = {
                "_type": "vless",
                "host": host,
                "port": int(port),
                "uuid": userinfo,
                "path": unquote(parsed.path),
                "_raw": uri
            }
            
            node.update(params)
            return node
            
        except Exception as e:
            log(f"VLESS解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_trojan(uri):
        """解析Trojan协议"""
        try:
            parsed = urlparse(uri)
            if '@' not in parsed.netloc:
                return None
                
            password, hostport = parsed.netloc.split('@', 1)
            if ':' in hostport:
                host, port = hostport.rsplit(':', 1)
            else:
                host = hostport
                port = "443"
            
            query_params = parse_qs(parsed.query)
            params = {}
            for key, value in query_params.items():
                params[key] = unquote(value[0])
            
            node = {
                "_type": "trojan",
                "host": host,
                "port": int(port),
                "password": password,
                "path": unquote(parsed.path),
                "_raw": uri
            }
            
            node.update(params)
            return node
            
        except Exception as e:
            log(f"Trojan解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_node(raw_line):
        """统一解析入口"""
        raw_line = raw_line.strip()
        if not raw_line:
            return None
        
        if raw_line.startswith("ss://"):
            return NodeParser.parse_ss(raw_line)
        elif raw_line.startswith("vmess://"):
            return NodeParser.parse_vmess(raw_line)
        elif raw_line.startswith("vless://"):
            return NodeParser.parse_vless(raw_line)
        elif raw_line.startswith("trojan://"):
            return NodeParser.parse_trojan(raw_line)
        
        return None

# ================== Xray配置生成器（增强版） ==================
class XrayConfigGenerator:
    """生成Xray配置（处理配置冲突）"""
    
    @staticmethod
    def get_stream_settings(node):
        """根据节点类型生成streamSettings（处理配置冲突）"""
        net_type = node.get("net", node.get("type", "tcp"))
        security = node.get("tls", node.get("security", "none"))
        
        base_settings = {
            "network": net_type,
            "security": security,
        }
        
        # 根据网络类型设置相应的参数（避免配置冲突）
        if net_type == "tcp":
            base_settings["tcpSettings"] = {
                "header": {
                    "type": node.get("type", "none")
                }
            }
            # TCP协议不设置path，即使节点配置中有path参数
            
        elif net_type == "ws":
            ws_headers = {}
            host_header = node.get("host") or node.get("sni") or node.get("host", "")
            if host_header:
                ws_headers["Host"] = host_header
            
            base_settings["wsSettings"] = {
                "path": node.get("path", "/"),  # WebSocket需要path
                "headers": ws_headers
            }
        
        elif net_type == "http":
            base_settings["httpSettings"] = {
                "host": [node.get("host") or node.get("sni") or node.get("host", "")],
                "path": node.get("path", "/")  # HTTP/2需要path
            }
        
        # REALITY配置
        if security == "reality":
            base_settings["realitySettings"] = {
                "show": False,
                "fingerprint": node.get("fp", "firefox"),
                "serverName": node.get("sni", ""),
                "publicKey": node.get("pbk", ""),
                "shortId": node.get("sid", ""),
                "spiderX": "/"
            }
        
        # TLS配置
        elif security == "tls":
            tls_settings = {
                "serverName": node.get("sni") or node.get("host") or node.get("host", ""),
            }
            
            if node.get("fp"):
                tls_settings["fingerprint"] = node.get("fp")
            
            if node.get("alpn"):
                tls_settings["alpn"] = node.get("alpn").split(",")
            
            base_settings["tlsSettings"] = tls_settings
        
        return base_settings
    
    @staticmethod
    def generate_config(node, local_port):
        """生成完整的Xray配置"""
        # 入站配置（SOCKS代理）
        inbound = {
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False,
                "userLevel": 0
            }
        }
        
        # 出站配置
        if node["_type"] == "ss":
            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": node["host"],
                        "port": node["port"],
                        "method": node["method"],
                        "password": node["password"],
                        "level": 0
                    }]
                },
                "streamSettings": XrayConfigGenerator.get_stream_settings(node)
            }
        
        elif node["_type"] == "vmess":
            # 用户认证配置
            user_config = {
                "id": node["uuid"],
                "alterId": node.get("aid", 0),
                "security": node.get("scy", "auto"),
                "level": 0
            }
            
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": node["host"],
                        "port": node["port"],
                        "users": [user_config]
                    }]
                },
                "streamSettings": XrayConfigGenerator.get_stream_settings(node)
            }
        
        elif node["_type"] == "vless":
            user_config = {
                "id": node["uuid"],
                "encryption": node.get("encryption", "none"),
                "flow": node.get("flow", ""),
                "level": 0
            }
            
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": node["host"],
                        "port": node["port"],
                        "users": [user_config]
                    }]
                },
                "streamSettings": XrayConfigGenerator.get_stream_settings(node)
            }
        
        elif node["_type"] == "trojan":
            outbound = {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": node["host"],
                        "port": node["port"],
                        "password": node["password"],
                        "level": 0
                    }]
                },
                "streamSettings": XrayConfigGenerator.get_stream_settings(node)
            }
        
        else:
            raise ValueError(f"不支持的协议类型: {node['_type']}")
        
        # 完整的Xray配置
        return {
            "log": {
                "loglevel": "warning",
            },
            "inbounds": [inbound],
            "outbounds": [
                outbound,
                {
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": {}
                }
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct"
                    }
                ]
            }
        }

# ================== 节点测试器（增强版） ==================
class NodeTester:
    """节点测试管理器"""
    
    def __init__(self):
        self.active_processes = {}
        self.temp_files = []
    
    def cleanup(self):
        """清理资源"""
        for pid, process in self.active_processes.items():
            try:
                process.terminate()
                process.wait(timeout=3)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        for temp_file in self.temp_files:
            try:
                os.remove(temp_file)
            except:
                pass
    
    def test_single_node(self, node, index):
        """测试单个节点（增强错误处理）"""
        # 先验证配置
        config_ok, config_msg = validate_xray_config(node)
        if not config_ok:
            return False, config_msg
        
        # REALITY协议：只测TCP
        if node.get("security") == "reality":
            tcp_ok, tcp_reason = robust_tcp_test(node["host"], node["port"])
            if tcp_ok:
                return True, "TCP连接通过"
            else:
                return False, classify_error(tcp_reason, node)
        
        # 其他协议：完整测试流程
        socks_port = SOCKS_BASE + index
        config_path = f"/tmp/xray_test_{index}_{int(time.time())}.json"
        process = None
        
        try:
            # 生成配置
            config = XrayConfigGenerator.generate_config(node, socks_port)
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.temp_files.append(config_path)
            
            # 启动Xray（捕获错误输出）
            process = subprocess.Popen(
                [XRAY_BIN, "run", "-config", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            self.active_processes[process.pid] = process
            time.sleep(XRAY_START_DELAY)
            
            # 检查进程是否存活
            if process.poll() is not None:
                _, stderr = process.communicate()
                error_msg = stderr.decode('utf-8', errors='ignore') if stderr else "未知错误"
                return False, f"Xray启动失败: {error_msg[:100]}"
            
            # TCP连接测试
            tcp_ok, tcp_reason = robust_tcp_test(node["host"], node["port"])
            if not tcp_ok:
                return False, classify_error(tcp_reason, node)
            
            # HTTP测试
            http_ok, latency = http_test_via_socks(socks_port)
            if http_ok:
                return True, f"HTTP延迟: {latency}ms"
            else:
                return False, "HTTP代理失败"
                
        except Exception as e:
            return False, f"测试异常: {str(e)}"
        finally:
            if node.get("security") != "reality":
                if process and process.poll() is None:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        process.wait(timeout=2)
                    except:
                        try:
                            process.kill()
                        except:
                            pass
                
                if process and process.pid in self.active_processes:
                    del self.active_processes[process.pid]
            
            try:
                if os.path.exists(config_path):
                    os.remove(config_path)
                    if config_path in self.temp_files:
                        self.temp_files.remove(config_path)
            except:
                pass

# ================== 主程序 ==================
def main():
    try:
        initialize()
        
        # 读取订阅文件并进行协议筛选
        supported_protocols = ["ss://", "vmess://", "vless://", "trojan://"]
        raw_lines = []
        
        with open(SUB_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split()
                for part in parts:
                    if any(part.startswith(proto) for proto in supported_protocols):
                        raw_lines.append(part)
        
        if not raw_lines:
            log("订阅文件中没有找到支持的协议节点", "ERROR")
            return
        
        # 解析节点
        nodes = []
        parser = NodeParser()
        
        for raw in raw_lines:
            node = parser.parse_node(raw)
            if node:
                nodes.append(node)
        
        log(f"成功解析节点: {len(nodes)}个", "SUCCESS")
        
        if not nodes:
            log("没有找到有效节点，请检查订阅文件格式", "ERROR")
            return
        
        # 测试节点
        tester = NodeTester()
        good_nodes = []
        bad_nodes = []
        
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_node = {
                    executor.submit(tester.test_single_node, node, idx): (idx, node) 
                    for idx, node in enumerate(nodes)
                }
                
                completed = 0
                for future in as_completed(future_to_node):
                    idx, node = future_to_node[future]
                    
                    try:
                        success, reason = future.result()
                        with lock:
                            if success:
                                # 构建协议信息字符串
                                protocol_info = node['_type']
                                if node.get('security') == 'reality':
                                    protocol_info += '+REALITY'
                                elif node.get('security') == 'tls' or node.get('tls'):
                                    protocol_info += '+TLS'
                                if node.get('type') and node.get('type') != 'tcp':
                                    protocol_info += f"+{node['type'].upper()}"
                                
                                # 解析延迟信息
                                if 'ms' in reason:
                                    latency = reason.split(' ')[-1].replace('ms', '')
                                    log(f"✅ [{idx:3d}] {protocol_info:20} | 延迟: {latency}ms", "SUCCESS")
                                else:
                                    log(f"✅ [{idx:3d}] {protocol_info:20} | {reason}", "SUCCESS")
                                good_nodes.append(node["_raw"])
                            else:
                                # 详细错误分类
                                error_detail = classify_error(reason, node)
                                log(f"❌ [{idx:3d}] {node['_type']:20} | {error_detail}", "ERROR")
                                bad_nodes.append(f"{node['_raw']}  # {error_detail}")
                            
                            completed += 1
                            if completed % 10 == 0 or completed == len(nodes):
                                current_success = len(good_nodes)
                                current_rate = (current_success / completed) * 100
                                log(f"📊 进度: {completed}/{len(nodes)} | 成功率: {current_rate:.1f}% | 可用: {current_success}", "INFO")
                                
                    except Exception as e:
                        with lock:
                            error_detail = f"测试异常: {str(e)}"
                            log(f"❌ [{idx:3d}] {node['_type']:20} | {error_detail}", "ERROR")
                            bad_nodes.append(f"{node['_raw']}  # {error_detail}")
                            completed += 1
            
            # 保存结果
            with open(GOOD_FILE, 'w', encoding='utf-8') as f:
                f.write("\n".join(good_nodes))
            
            with open(BAD_FILE, 'w', encoding='utf-8') as f:
                f.write("\n".join(bad_nodes))
            
            # 输出详细统计信息
            success_rate = (len(good_nodes) / len(nodes)) * 100 if nodes else 0
            
            # 按协议分类统计
            protocol_stats = {}
            for node in nodes:
                proto = node['_type']
                if proto not in protocol_stats:
                    protocol_stats[proto] = {'total': 0, 'success': 0}
                protocol_stats[proto]['total'] += 1
            
            for good_raw in good_nodes:
                # 从原始链接判断协议类型
                if good_raw.startswith('ss://'):
                    proto = 'ss'
                elif good_raw.startswith('vmess://'):
                    proto = 'vmess'
                elif good_raw.startswith('vless://'):
                    proto = 'vless'
                elif good_raw.startswith('trojan://'):
                    proto = 'trojan'
                else:
                    continue
                
                if proto in protocol_stats:
                    protocol_stats[proto]['success'] += 1
            
            log(f"🎯 测试完成!", "SUCCESS")
            log(f"📊 总体统计:", "INFO")
            log(f"   ✅ 可用节点: {len(good_nodes)}个", "SUCCESS")
            log(f"   ❌ 失败节点: {len(bad_nodes)}个", "ERROR")
            log(f"   📈 成功率: {success_rate:.1f}%", "INFO")
            
# 继续补充主程序
            # 协议分布统计
            if protocol_stats:
                log(f"📋 协议分布统计:", "INFO")
                for proto, stats in protocol_stats.items():
                    total = stats['total']
                    success = stats['success']
                    rate = (success / total) * 100 if total > 0 else 0
                    status_icon = "✅" if rate > 50 else "⚠️" if rate > 20 else "❌"
                    log(f"   {status_icon} {proto:8}: {success}/{total} ({rate:.1f}%)", "INFO")
            
            # 错误类型统计
            error_stats = {}
            for bad_line in bad_nodes:
                if "#" in bad_line:
                    error_type = bad_line.split("#")[1].strip()
                    if error_type not in error_stats:
                        error_stats[error_type] = 0
                    error_stats[error_type] += 1
            
            if error_stats:
                log(f"🔍 错误类型分析:", "INFO")
                for error_type, count in error_stats.items():
                    log(f"   ⚠️ {error_type}: {count}个", "WARN")
            
            log(f"📁 结果已保存: {GOOD_FILE}, {BAD_FILE}", "INFO")
            
        finally:
            tester.cleanup()
            
    except FileNotFoundError as e:
        log(str(e), "ERROR")
        sys.exit(1)
    except KeyboardInterrupt:
        log("用户中断测试", "WARN")
    except Exception as e:
        log(f"程序异常: {e}", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()
