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

# ================== 节点解析器（修复版） ==================
class NodeParser:
    """统一节点解析器（修复SS解析问题）"""
    
    @staticmethod
    def parse_ss(uri):
        """解析SS协议（修复分割错误）"""
        try:
            if "#" in uri:
                uri = uri.split("#", 1)[0]
            
            # 处理SIP002格式
            if "@" in uri:
                # 格式: ss://base64@host:port
                parts = uri[5:].split("@", 1)
                if len(parts) != 2:
                    return None
                
                # 尝试解码base64部分
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
                # 旧格式: ss://base64
                try:
                    decoded = base64.b64decode(uri[5:] + "===").decode('utf-8')
                    if "@" in decoded:
                        method_password, server_part = decoded.split("@", 1)
                        method, password = method_password.split(":", 1)
                    else:
                        return None
                except:
                    return None
            
            # 分割服务器和端口
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
        """解析VMess协议"""
        try:
            # 解码Base64
            decoded_json = base64.b64decode(uri[8:] + "===").decode('utf-8')
            config = json.loads(decoded_json)
            
            # 构建节点配置
            node = {
                "_type": "vmess",
                "host": config["add"],
                "port": int(config["port"]),
                "uuid": config["id"],
                "aid": int(config.get("aid", 0)),
                "_raw": uri
            }
            
            # 添加可选字段
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
        """解析VLESS协议（支持REALITY）"""
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
            
            # 解析查询参数
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
            
            # 添加所有查询参数
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
            
            # 解析查询参数
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
            
            # 添加所有查询参数
            node.update(params)
            return node
            
        except Exception as e:
            log(f"Trojan解析失败: {uri[:30]}... -> {e}", "ERROR")
            return None
    
    @staticmethod
    def parse_node(raw_line):
        """统一解析入口（只处理支持的协议）"""
        raw_line = raw_line.strip()
        if not raw_line:
            return None
        
        # 现在这里只会收到支持的协议
        if raw_line.startswith("ss://"):
            return NodeParser.parse_ss(raw_line)
        elif raw_line.startswith("vmess://"):
            return NodeParser.parse_vmess(raw_line)
        elif raw_line.startswith("vless://"):
            return NodeParser.parse_vless(raw_line)
        elif raw_line.startswith("trojan://"):
            return NodeParser.parse_trojan(raw_line)
        
        # 理论上不会走到这里，因为前面已经筛选过了
        return None

# ================== Xray配置生成器 ==================
class XrayConfigGenerator:
    """生成Xray配置（支持所有协议和传输）"""
    
    @staticmethod
    def get_stream_settings(node):
        """根据节点类型生成streamSettings"""
        base_settings = {
            "network": node.get("type", "tcp"),
            "security": node.get("security", node.get("tls", "none")),
        }
        
        # TCP设置
        if base_settings["network"] == "tcp":
            base_settings["tcpSettings"] = {
                "header": {
                    "type": "none"
                }
            }
        
        # WebSocket设置
        elif base_settings["network"] == "ws":
            ws_headers = {}
            host_header = node.get("host") or node.get("sni") or node.get("host", "")
            if host_header:
                ws_headers["Host"] = host_header
            
            base_settings["wsSettings"] = {
                "path": node.get("path", "/"),
                "headers": ws_headers
            }
        
        # REALITY配置
        if base_settings["security"] == "reality":
            base_settings["realitySettings"] = {
                "show": False,
                "fingerprint": node.get("fp", "firefox"),
                "serverName": node.get("sni", ""),
                "publicKey": node.get("pbk", ""),
                "shortId": node.get("sid", ""),
                "spiderX": "/"
            }
        
        # TLS配置
        elif base_settings["security"] == "tls":
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

# ================== 节点测试器（修复版） ==================
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
        # REALITY协议：只测TCP，不启动Xray
        if node.get("security") == "reality":
            tcp_ok, tcp_reason = robust_tcp_test(node["host"], node["port"])
            if tcp_ok:
                return True, "TCP连接通过"
            else:
                return False, tcp_reason
        
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
            
            # 启动Xray
            process = subprocess.Popen(
                [XRAY_BIN, "run", "-config", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            
            self.active_processes[process.pid] = process
            time.sleep(XRAY_START_DELAY)
            
            # 检查进程是否存活
            if process.poll() is not None:
                return False, "Xray进程启动失败"
            
            # 进行TCP连接测试
            tcp_ok, tcp_reason = robust_tcp_test(node["host"], node["port"])
            if not tcp_ok:
                return False, tcp_reason
            
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
        supported_protocols = ["ss://", "vmess://", "vless://", "trojan://"]
        
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
                                
                                log(f"✅ [{idx:3d}] {protocol_info:20} | {reason}", "SUCCESS")
                                good_nodes.append(node["_raw"])
                            else:
                                # 详细错误分类
                                error_detail = ""
                                if "tcp_failed" in reason or "TCP连接失败" in reason:
                                    error_detail = "TCP连接失败"
                                elif "http_failed" in reason or "HTTP代理失败" in reason:
                                    error_detail = "HTTP代理失败" 
                                elif "xray进程启动失败" in reason or "Xray进程启动失败" in reason:
                                    error_detail = "Xray配置错误"
                                elif "DNS解析失败" in reason:
                                    error_detail = "域名解析失败"
                                elif "连接超时" in reason:
                                    error_detail = "连接超时"
                                else:
                                    error_detail = reason
                                    
                                log(f"❌ [{idx:3d}] {node['_type']:20} | 失败: {error_detail}", "ERROR")
                                bad_nodes.append(f"{node['_raw']}  # {error_detail}")
                            
                            completed += 1
                            if completed % 10 == 0 or completed == len(nodes):
                                current_success = len(good_nodes)
                                current_rate = (current_success / completed) * 100
                                log(f"📊 进度: {completed}/{len(nodes)} | 成功率: {current_rate:.1f}% | 可用: {current_success}", "INFO")
                                
                    except Exception as e:
                        with lock:
                            log(f"❌ [{idx:3d}] 测试异常: {e}", "ERROR")
                            bad_nodes.append(f"{node['_raw']}  # exception")
                            completed += 1
            
            # 保存结果
            with open(GOOD_FILE, 'w', encoding='utf-8') as f:
                f.write("\n".join(good_nodes))
            
            with open(BAD_FILE, 'w', encoding='utf-8') as f:
                f.write("\n".join(bad_nodes))
            
            # 输出统计信息
            success_rate = (len(good_nodes) / len(nodes)) * 100
            log(f"🎯 测试完成! 可用: {len(good_nodes)}/{len(nodes)} 成功率: {success_rate:.1f}%", "SUCCESS")
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
