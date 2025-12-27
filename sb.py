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
SINGBOX_BIN = "./sing-box/sing-box"
SUB_FILE = "all_configs.txt"
GOOD_FILE = "ping.txt"
BAD_FILE = "bad.txt"

MAX_WORKERS = 3
TCP_TIMEOUT = 8
HTTP_TIMEOUT = 10
SOCKS_BASE = 30000
SINGBOX_START_DELAY = 2

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
    if not os.path.exists(SINGBOX_BIN):
        raise FileNotFoundError(f"Singbox 不存在: {SINGBOX_BIN}")
    
    if not os.access(SINGBOX_BIN, os.X_OK):
        os.chmod(SINGBOX_BIN, 0o755)
        print(f"[INFO] 已添加执行权限: {SINGBOX_BIN}")
    
    if not os.path.exists(SUB_FILE):
        raise FileNotFoundError(f"订阅文件不存在: {SUB_FILE}")
    
    print(f"[INFO] 环境检查通过: Singbox={SINGBOX_BIN}, Workers={MAX_WORKERS}")

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

def validate_singbox_config(node):
    """验证Singbox配置的完整性"""
    required_fields = {
        "ss": ["host", "port", "method", "password"],
        "ssr": ["host", "port", "method", "password", "protocol", "obfs"],
        "vmess": ["host", "port", "uuid"],
        "vless": ["host", "port", "uuid"], 
        "trojan": ["host", "port", "password"],
        "hysteria": ["host", "port", "auth"],
        "hysteria2": ["host", "port", "password"],
        "tuic": ["host", "port", "uuid", "password"],
        "wireguard": ["server", "server_port", "private_key", "peer_public_key", "local_address"],
        "http": ["host", "port"]
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
    
    # HTTP代理特殊验证
    if proto == "http":
        if node.get("scheme") == "https" and not node.get("sni") and not node.get("host"):
            return False, "HTTPS代理需要server_name"
    
    # WireGuard特殊验证
    if proto == "wireguard":
        # 检查local_address格式
        local_address = node.get("local_address")
        if local_address:
            if isinstance(local_address, str):
                addresses = [local_address]
            else:
                addresses = local_address
            
            for addr in addresses:
                if not ('/' in addr and (':' in addr or '.' in addr)):
                    return False, f"WireGuard local_address格式错误: {addr}"
    
    return True, "配置验证通过"

def classify_error(reason, node):
    """更精确的错误分类"""
    reason_lower = reason.lower()
    
    if "singbox" in reason_lower or "配置" in reason_lower:
        config_ok, config_msg = validate_singbox_config(node)
        if not config_ok:
            return f"配置错误: {config_msg}"
        return "Singbox进程启动失败"
    
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

# ================== 节点解析器 ==================
class NodeParser:
    """统一节点解析器（支持所有协议）"""
    
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
    def parse_ssr(uri):
        """解析SSR协议"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            encoded = uri[6:]
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding
            
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            
            if "?" in decoded:
                main_part, param_part = decoded.split("?", 1)
            else:
                main_part, param_part = decoded, ""
            
            parts = main_part.split(":")
            if len(parts) < 6:
                return None
            
            host = parts[0]
            port = int(parts[1])
            protocol = parts[2]
            method = parts[3]
            obfs = parts[4]
            
            password_encoded = parts[5]
            try:
                password = base64.b64decode(password_encoded + "===").decode('utf-8')
            except:
                password = password_encoded
            
            params = {}
            if param_part:
                for param in param_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = unquote(value)
            
            node = {
                "_type": "ssr",
                "host": host,
                "port": port,
                "method": method,
                "password": password,
                "protocol": protocol,
                "obfs": obfs,
                "_raw": uri
            }
            
            if "obfsparam" in params:
                node["obfs_param"] = params["obfsparam"]
            if "protoparam" in params:
                node["protocol_param"] = params["protoparam"]
            if "remarks" in params:
                node["remarks"] = params["remarks"]
            if "group" in params:
                node["group"] = params["group"]
            
            return node
            
        except Exception as e:
            log(f"SSR解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_hysteria(uri):
        """解析Hysteria协议"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            parsed = urlparse(uri)
            host = parsed.hostname
            port = parsed.port or 443
            
            query_params = parse_qs(parsed.query)
            params = {}
            for key, value in query_params.items():
                params[key] = unquote(value[0]) if value else ""
            
            node = {
                "_type": "hysteria",
                "host": host,
                "port": port,
                "_raw": uri
            }
            
            if "auth" in params:
                node["auth"] = params["auth"]
            if "peer" in params:
                node["sni"] = params["peer"]
            if "insecure" in params:
                node["insecure"] = params["insecure"] == "1"
            if "alpn" in params:
                node["alpn"] = params["alpn"]
            if "upmbps" in params:
                try:
                    node["up_mbps"] = int(params["upmbps"])
                except:
                    node["up_mbps"] = 100
            if "downmbps" in params:
                try:
                    node["down_mbps"] = int(params["downmbps"])
                except:
                    node["down_mbps"] = 100
            if "obfs" in params:
                node["obfs"] = params["obfs"]
            if "protocol" in params:
                node["protocol"] = params["protocol"]
            
            return node
            
        except Exception as e:
            log(f"Hysteria解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_hysteria2(uri):
        """解析Hysteria2协议"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            parsed = urlparse(uri)
            host = parsed.hostname
            port = parsed.port or 443
            
            password = None
            if parsed.username:
                password = parsed.username
            elif "@" in parsed.netloc:
                password_part = parsed.netloc.split("@")[0]
                try:
                    password = base64.b64decode(password_part + "===").decode('utf-8')
                except:
                    password = password_part
            
            query_params = parse_qs(parsed.query)
            params = {}
            for key, value in query_params.items():
                params[key] = unquote(value[0]) if value else ""
            
            node = {
                "_type": "hysteria2",
                "host": host,
                "port": port,
                "_raw": uri
            }
            
            if password:
                node["password"] = password
            
            if "sni" in params:
                node["sni"] = params["sni"]
            if "insecure" in params:
                node["insecure"] = params["insecure"] == "1" or params["insecure"].lower() == "true"
            if "alpn" in params:
                node["alpn"] = params["alpn"]
            if "obfs" in params:
                node["obfs"] = params["obfs"]
            if "obfs-password" in params:
                node["obfs_password"] = params["obfs-password"]
            if "up" in params:
                try:
                    node["up_mbps"] = int(params["up"])
                except:
                    pass
            if "down" in params:
                try:
                    node["down_mbps"] = int(params["down"])
                except:
                    pass
            if "pin" in params:
                node["pin"] = params["pin"]
            
            return node
            
        except Exception as e:
            log(f"Hysteria2解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_tuic(uri):
        """解析TUIC协议"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            parsed = urlparse(uri)
            host = parsed.hostname
            port = parsed.port or 443
            
            uuid = parsed.username
            password = parsed.password
            
            query_params = parse_qs(parsed.query)
            params = {}
            for key, value in query_params.items():
                params[key] = unquote(value[0]) if value else ""
            
            node = {
                "_type": "tuic",
                "host": host,
                "port": port,
                "uuid": uuid,
                "password": password,
                "_raw": uri
            }
            
            if "sni" in params:
                node["sni"] = params["sni"]
            if "alpn" in params:
                node["alpn"] = params["alpn"]
            if "disable_sni" in params:
                node["disable_sni"] = params["disable_sni"] == "true"
            if "reduce_rtt" in params:
                node["reduce_rtt"] = params["reduce_rtt"] == "true"
            
            return node
            
        except Exception as e:
            log(f"TUIC解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_wireguard(uri):
        """解析WireGuard协议"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            parsed = urlparse(uri)
            if '@' not in parsed.netloc:
                return None
                
            private_key, server_part = parsed.netloc.split('@', 1)
            if ':' in server_part:
                server, port = server_part.rsplit(':', 1)
            else:
                server = server_part
                port = "51820"
                
            query_params = parse_qs(parsed.query)
            params = {}
            for key, value in query_params.items():
                params[key] = unquote(value[0]) if value else ""
            
            node = {
                "_type": "wireguard",
                "server": server,
                "server_port": int(port),
                "private_key": private_key,
                "_raw": uri
            }
            
            if "public_key" in params:
                node["peer_public_key"] = params["public_key"]
            if "local_address" in params:
                node["local_address"] = params["local_address"]
            if "preshared_key" in params:
                node["preshared_key"] = params["preshared_key"]
            if "mtu" in params:
                node["mtu"] = int(params["mtu"])
            if "reserved" in params:
                node["reserved"] = params["reserved"]
            if "dns" in params:
                node["dns"] = params["dns"]
            
            return node
            
        except Exception as e:
            log(f"WireGuard解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_vmess(uri):
        """解析VMess协议（自动修正配置冲突）"""
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
            
            if not node["host"] or not node["port"] or not node["uuid"]:
                return None
            
            net_type = config.get("net", "tcp")
            path = config.get("path", "")
            
            # 自动修正：TCP协议不应该有path
            if net_type == "tcp" and path:
                log(f"⚠️ VMess配置修正: TCP协议移除非法的path参数: {path}", "WARN")
                node["net"] = net_type
                node["type"] = config.get("type", "none")
            else:
                optional_fields = ["net", "type", "tls", "sni", "path", "host", "alpn", "fp", "scy"]
                for field in optional_fields:
                    if field in config and config[field]:
                        node[field] = config[field]
            
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
    def parse_http(uri):
        """解析HTTP/HTTPS代理协议"""
        try:
            parsed = urlparse(uri)
            
            username = parsed.username
            password = parsed.password
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            
            if not host or not port:
                return None
            
            node = {
                "_type": "http",
                "host": host,
                "port": port,
                "scheme": parsed.scheme,
                "_raw": uri
            }
            
            if username:
                node["username"] = unquote(username)
            if password:
                node["password"] = unquote(password)
            
            query_params = parse_qs(parsed.query)
            for key, value in query_params.items():
                node[key] = unquote(value[0]) if value else ""
            
            return node
            
        except Exception as e:
            log(f"HTTP代理解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_node(raw_line):
        """统一解析入口"""
        raw_line = raw_line.strip()
        if not raw_line:
            return None
        
        if raw_line.startswith("ss://"):
            return NodeParser.parse_ss(raw_line)
        elif raw_line.startswith("ssr://"):
            return NodeParser.parse_ssr(raw_line)
        elif raw_line.startswith("vmess://"):
            return NodeParser.parse_vmess(raw_line)
        elif raw_line.startswith("vless://"):
            return NodeParser.parse_vless(raw_line)
        elif raw_line.startswith("trojan://"):
            return NodeParser.parse_trojan(raw_line)
        elif raw_line.startswith("hy2://") or raw_line.startswith("hysteria2://"):
            return NodeParser.parse_hysteria2(raw_line)
        elif raw_line.startswith("hy://") or raw_line.startswith("hysteria://"):
            return NodeParser.parse_hysteria(raw_line)
        elif raw_line.startswith("tuic://"):
            return NodeParser.parse_tuic(raw_line)
        elif raw_line.startswith("wireguard://"):
            return NodeParser.parse_wireguard(raw_line)
        elif raw_line.startswith("https://") or raw_line.startswith("http://"):
            return NodeParser.parse_http(raw_line)
        
        return None

# ================== Singbox配置生成器 ==================
class SingboxConfigGenerator:
    """生成Singbox配置（支持所有协议）"""
    
    @staticmethod
    def generate_outbound(node):
        """根据节点类型生成outbound配置"""
        protocol = node["_type"]
        
        if protocol == "ss":
            return {
                "type": "shadowsocks",
                "server": node["host"],
                "server_port": node["port"],
                "method": node["method"],
                "password": node["password"]
            }
        
        elif protocol == "ssr":
            outbound = {
                "type": "shadowsocksr",
                "server": node["host"],
                "server_port": node["port"],
                "method": node["method"],
                "password": node["password"],
                "protocol": node["protocol"],
                "obfs": node["obfs"]
            }
            
            if "obfs_param" in node:
                outbound["obfs_param"] = node["obfs_param"]
            if "protocol_param" in node:
                outbound["protocol_param"] = node["protocol_param"]
            
            return outbound
        
        elif protocol == "vmess":
            outbound = {
                "type": "vmess",
                "server": node["host"],
                "server_port": node["port"],
                "uuid": node["uuid"],
                "alter_id": node.get("aid", 0),
                "security": node.get("scy", "auto")
            }
            
            net_type = node.get("net", "tcp")
            if net_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": node.get("path", "/"),
                    "headers": {
                        "Host": node.get("host") or node.get("sni", "")
                    }
                }
            elif net_type == "tcp":
                outbound["transport"] = {"type": "tcp"}
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": node.get("path", "")
                }
            elif net_type == "http":
                outbound["transport"] = {
                    "type": "http",
                    "host": [node.get("host") or node.get("sni", "")],
                    "path": node.get("path", "/")
                }
            
            if node.get("tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node.get("sni") or node.get("host", "")
                }
            
            return outbound
        
        elif protocol == "vless":
            outbound = {
                "type": "vless",
                "server": node["host"],
                "server_port": node["port"],
                "uuid": node["uuid"],
                "flow": node.get("flow", "")
            }
            
            net_type = node.get("type", "tcp")
            if net_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": node.get("path", "/"),
                    "headers": {
                        "Host": node.get("host") or node.get("sni", "")
                    }
                }
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": node.get("path", "")
                }
            elif net_type == "h2":
                outbound["transport"] = {
                    "type": "http",
                    "host": [node.get("host") or node.get("sni", "")],
                    "path": node.get("path", "/")
                }
            else:
                outbound["transport"] = {"type": "tcp"}
            
            if node.get("security") == "tls" or node.get("tls"):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node.get("sni") or node.get("host", "")
                }
            
            if node.get("security") == "reality":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node.get("sni", ""),
                    "reality": {
                        "enabled": True,
                        "public_key": node.get("pbk", ""),
                        "short_id": node.get("sid", "")
                    }
                }
            
            return outbound
        
        elif protocol == "trojan":
            outbound = {
                "type": "trojan",
                "server": node["host"],
                "server_port": node["port"],
                "password": node["password"]
            }
            
            net_type = node.get("type", "tcp")
            if net_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": node.get("path", "/"),
                    "headers": {
                        "Host": node.get("host") or node.get("sni", "")
                    }
                }
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": node.get("path", "")
                }
            else:
                outbound["transport"] = {"type": "tcp"}
            
            if node.get("security") == "tls" or node.get("tls"):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node.get("sni") or node.get("host", "")
                }
            
            return outbound
        
        elif protocol == "hysteria":
            outbound = {
                "type": "hysteria",
                "server": f"{node['host']}:{node['port']}",
                "up_mbps": node.get("up_mbps", 100),
                "down_mbps": node.get("down_mbps", 100),
            }
            
            if "auth" in node:
                outbound["auth"] = node["auth"]
            elif "auth_str" in node:
                outbound["auth_str"] = node["auth_str"]
            
            tls_config = {"enabled": True}
            if "sni" in node:
                tls_config["server_name"] = node["sni"]
            if "insecure" in node:
                tls_config["insecure"] = node["insecure"]
            if "alpn" in node:
                alpn_value = node["alpn"]
                if isinstance(alpn_value, str):
                    tls_config["alpn"] = [alpn_value]
                else:
                    tls_config["alpn"] = alpn_value
            
            outbound["tls"] = tls_config
            
            if "obfs" in node:
                outbound["obfs"] = node["obfs"]
                if "obfs_password" in node:
                    outbound["obfs_password"] = node["obfs_password"]
            
            return outbound
        
        elif protocol == "hysteria2":
            outbound = {
                "type": "hysteria2",
                "server": f"{node['host']}:{node['port']}",
                "server_port": node["port"]
            }
            
            if "password" in node:
                outbound["password"] = node["password"]
            elif "auth" in node:
                outbound["password"] = node["auth"]
            
            if "up_mbps" in node:
                outbound["up_mbps"] = node["up_mbps"]
            if "down_mbps" in node:
                outbound["down_mbps"] = node["down_mbps"]
            
            tls_config = {"enabled": True}
            if "sni" in node:
                tls_config["server_name"] = node["sni"]
            elif "host" in node:
                tls_config["server_name"] = node["host"]
            
            if "insecure" in node:
                tls_config["insecure"] = bool(node["insecure"])
            
            if "alpn" in node:
                alpn_value = node["alpn"]
                if isinstance(alpn_value, str):
                    tls_config["alpn"] = [alpn_value]
                else:
                    tls_config["alpn"] = alpn_value
            
            outbound["tls"] = tls_config
            
            if "obfs" in node:
                obfs_config = {"type": node["obfs"]}
                if "obfs_password" in node:
                    obfs_config["password"] = node["obfs_password"]
                outbound["obfs"] = obfs_config
            
            if "pin" in node:
                outbound["pin"] = node["pin"]
            
            return outbound
        
        elif protocol == "tuic":
            outbound = {
                "type": "tuic",
                "server": node["host"],
                "server_port": node["port"],
                "uuid": node["uuid"],
                "password": node["password"]
            }
            
            if "sni" in node:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node["sni"]
                }
            
            return outbound
        
        elif protocol == "wireguard":
            outbound = {
                "type": "wireguard",
                "server": node["server"],
                "server_port": node["server_port"],
                "private_key": node["private_key"],
                "mtu": node.get("mtu", 1408)
            }
            
            if "peer_public_key" in node:
                outbound["peer_public_key"] = node["peer_public_key"]
            else:
                raise ValueError("WireGuard配置缺少peer_public_key")
            
            local_address = node["local_address"]
            if isinstance(local_address, str):
                outbound["local_address"] = [local_address]
            else:
                outbound["local_address"] = local_address
            
            if "preshared_key" in node and node["preshared_key"]:
                outbound["preshared_key"] = node["preshared_key"]
            if "reserved" in node:
                outbound["reserved"] = node["reserved"]
            if "dns" in node:
                outbound["dns"] = node["dns"]
            if "workers" in node:
                outbound["workers"] = node["workers"]
            
            return outbound
        
        elif protocol == "http":
            outbound = {
                "type": "http",
                "server": node["host"],
                "server_port": node["port"]
            }
            
            if "username" in node and "password" in node:
                outbound["username"] = node["username"]
                outbound["password"] = node["password"]
            
            if node.get("scheme") == "https" or node.get("tls"):
                tls_config = {"enabled": True}
                
                if "sni" in node:
                    tls_config["server_name"] = node["sni"]
                elif "host" in node:
                    tls_config["server_name"] = node["host"]
                
                if "insecure" in node:
                    tls_config["insecure"] = bool(node["insecure"])
                
                outbound["tls"] = tls_config
            
            return outbound
        
        else:
            raise ValueError(f"不支持的协议类型: {protocol}")
    
    @staticmethod
    def generate_config(node, local_port):
        """生成完整的Singbox配置"""
        return {
            "log": {
                "level": "warn"
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": local_port,
                    "sniff": True
                }
            ],
            "outbounds": [
                SingboxConfigGenerator.generate_outbound(node),
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "route": {
                "rules": [
                    {
                        "inbound": ["socks-in"],
                        "outbound": "proxy"
                    }
                ]
            }
        }

# ================== 节点测试器 ==================
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
        """测试单个节点"""
        # 先验证配置
        config_ok, config_msg = validate_singbox_config(node)
        if not config_ok:
            return False, config_msg
        
        # REALITY协议：只测TCP，不启动Singbox
        if node.get("security") == "reality":
            tcp_ok, tcp_reason = robust_tcp_test(node["host"], node["port"])
            if tcp_ok:
                return True, "TCP连接通过"
            else:
                return False, classify_error(tcp_reason, node)
        
        # 其他协议：完整测试流程
        socks_port = SOCKS_BASE + index
        config_path = f"/tmp/singbox_test_{index}_{int(time.time())}.json"
        process = None
        
        try:
            # 生成配置
            config = SingboxConfigGenerator.generate_config(node, socks_port)
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.temp_files.append(config_path)
            
            # 启动Singbox
            process = subprocess.Popen(
                [SINGBOX_BIN, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            self.active_processes[process.pid] = process
            time.sleep(SINGBOX_START_DELAY)
            
            # 检查进程是否存活
            if process.poll() is not None:
                _, stderr = process.communicate()
                error_msg = stderr.decode('utf-8', errors='ignore') if stderr else "未知错误"
                return False, f"Singbox启动失败: {error_msg[:100]}"
            
            # 进行TCP连接测试
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
            # 清理进程（如果不是REALITY协议）
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
            
            # 清理临时文件
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
        # 初始化检查
        initialize()
        
        # 支持的协议列表
        supported_protocols = [
            "ss://", "ssr://", "vmess://", "vless://", "trojan://",
            "hy2://", "hysteria2://", "hy://", "hysteria://", 
            "tuic://", "wireguard://", "https://", "http://"
        ]
        
        # 读取订阅文件并进行协议筛选
        raw_lines = []
        with open(SUB_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split()
                for part in parts:
                    # 检查是否以支持的协议开头
                    is_supported = any(part.startswith(proto) for proto in supported_protocols)
                    if is_supported:
                        raw_lines.append(part)
                    # 不支持的协议直接跳过，不记录日志
        
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
            
            # 输出统计信息
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
                elif good_raw.startswith('hy2://') or good_raw.startswith('hysteria2://'):
                    proto = 'hysteria2'
                elif good_raw.startswith('hy://') or good_raw.startswith('hysteria://'):
                    proto = 'hysteria'
                elif good_raw.startswith('tuic://'):
                    proto = 'tuic'
                elif good_raw.startswith('wireguard://'):
                    proto = 'wireguard'
                elif good_raw.startswith('https://') or good_raw.startswith('http://'):
                    proto = 'http'
                else:
                    continue
                
                if proto in protocol_stats:
                    protocol_stats[proto]['success'] += 1
            
            log(f"🎯 测试完成!", "SUCCESS")
            log(f"📊 总体统计:", "INFO")
            log(f"   ✅ 可用节点: {len(good_nodes)}个", "SUCCESS")
            log(f"   ❌ 失败节点: {len(bad_nodes)}个", "ERROR")
            log(f"   📈 成功率: {success_rate:.1f}%", "INFO")
            
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
                
