#!/usr/bin/env python3
import os
import time
import socket
import subprocess
import json
import re
import requests
from urllib.parse import urlparse
import base64
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings('ignore', category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class XrayNodeTester:
    def __init__(self, enable_ping=True, enable_tcp=True, enable_speedtest=True, enable_tls_http_test=True):
        self.sub_file = "ping.txt"
        self.ping_timeout = 3
        self.tcp_timeout = 5
        self.speedtest_timeout = 15
        self.tls_http_timeout = 8
        self.enable_ping = enable_ping
        self.enable_tcp = enable_tcp
        self.enable_speedtest = enable_speedtest
        self.enable_tls_http_test = enable_tls_http_test
        self.xray_config_dir = "/tmp/xray_configs"
        
        os.makedirs(self.xray_config_dir, exist_ok=True)
        
        self.speedtest_files = [
            "http://httpbin.org/bytes/500000",  # 使用HTTP测试，避免证书问题
            "https://speed.cloudflare.com/__down?bytes=1000000",
        ]
        
        self.tls_test_sites = [
            "http://httpbin.org/get",  # 先用HTTP测试
            "https://www.google.com",
        ]
        
        print("=" * 60)
        print("Xray节点测试 - 调试版本")
        print("=" * 60)
    
    def read_nodes(self):
        """读取节点配置"""
        if not os.path.exists(self.sub_file):
            print(f"错误: 找不到 {self.sub_file}")
            return []
            
        nodes = []
        with open(self.sub_file, 'r', encoding='utf-8') as f:
            for line in f:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    nodes.append({
                        'config': clean_line,
                        'original_config': clean_line
                    })
        
        print(f"成功读取 {len(nodes)} 个节点")
        return nodes
    
    def extract_server_info(self, node_config):
        """提取服务器信息"""
        try:
            if node_config.startswith('vmess://'):
                encoded = node_config[8:]
                padding = 4 - len(encoded) % 4
                if padding != 4:
                    encoded += '=' * padding
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                config = json.loads(decoded)
                return config.get('add'), config.get('port')
            elif node_config.startswith('vless://') or node_config.startswith('trojan://'):
                parsed = urlparse(node_config)
                return parsed.hostname, parsed.port
            elif node_config.startswith('ss://'):
                if '@' in node_config:
                    host_port = node_config.split('@')[1].split('#')[0]
                    if ':' in host_port:
                        host, port = host_port.split(':')
                        return host, int(port)
                return None, None
            else:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', node_config)
                if match:
                    return match.group(1), int(match.group(2))
        except Exception as e:
            print(f"解析配置错误: {e}")
        return None, None
    
    def test_icmp_ping(self, host):
        """测试Ping"""
        if not self.enable_ping:
            return False, None
            
        try:
            cmd = ['ping', '-c', '2', '-W', '2', host]  # 减少ping次数
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                output = result.stdout
                if 'avg' in output:
                    match = re.search(r'(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', output)
                    if match:
                        return True, float(match.group(2))
            return False, None
        except Exception:
            return False, None
    
    def test_tcp_connect(self, host, port):
        """测试TCP连接"""
        if not self.enable_tcp:
            return False, None
            
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # 缩短超时时间
            result = sock.connect_ex((host, int(port)))
            latency = (time.time() - start_time) * 1000
            sock.close()
            return result == 0, latency
        except:
            return False, None
    
    def create_simple_xray_config(self, node_config, config_path):
        """创建简化的Xray配置"""
        try:
            host, port = self.extract_server_info(node_config)
            if not host or not port:
                return False
            
            # 基础配置
            config = {
                "log": {
                    "loglevel": "debug"  # 开启调试日志
                },
                "inbounds": [{
                    "tag": "socks-in",
                    "port": 10808,  # 使用不同端口避免冲突
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False,  # 先禁用UDP
                        "userLevel": 0
                    },
                    "sniffing": {
                        "enabled": False
                    }
                }],
                "outbounds": [{
                    "tag": "proxy-out",
                    "protocol": "freedom",
                    "settings": {}
                }],
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [
                        {
                            "type": "field",
                            "inboundTag": ["socks-in"],
                            "outboundTag": "proxy-out"
                        }
                    ]
                }
            }
            
            # 根据协议类型设置outbound
            if node_config.startswith('vmess://'):
                config = self._setup_vmess_outbound(config, node_config)
            elif node_config.startswith('vless://'):
                config = self._setup_vless_outbound(config, node_config)
            elif node_config.startswith('trojan://'):
                config = self._setup_trojan_outbound(config, node_config)
            elif node_config.startswith('ss://'):
                config = self._setup_ss_outbound(config, node_config)
            else:
                return False
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"✅ 配置文件已创建: {config_path}")
            return True
            
        except Exception as e:
            print(f"❌ 创建配置失败: {e}")
            return False
    
    def _setup_vmess_outbound(self, config, node_config):
        """设置VMess outbound"""
        try:
            encoded = node_config[8:]
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            decoded = base64.b64decode(encoded).decode('utf-8')
            vmess = json.loads(decoded)
            
            outbound = {
                "tag": "proxy-out",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": vmess.get("add"),
                        "port": int(vmess.get("port", 443)),
                        "users": [{
                            "id": vmess.get("id"),
                            "alterId": int(vmess.get("aid", 0)),
                            "security": vmess.get("scy", "auto"),
                            "level": 0
                        }]
                    }]
                },
                "streamSettings": {
                    "network": vmess.get("net", "tcp"),
                    "security": vmess.get("tls", "none")
                }
            }
            
            # 设置传输协议
            net = vmess.get("net", "tcp")
            if net == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": vmess.get("path", "/"),
                    "headers": {
                        "Host": vmess.get("host", "")
                    }
                }
            elif net == "h2":
                outbound["streamSettings"]["httpSettings"] = {
                    "path": vmess.get("path", "/"),
                    "host": [vmess.get("host", "")]
                }
            
            config["outbounds"][0] = outbound
            return config
        except Exception as e:
            print(f"VMess配置错误: {e}")
            return config
    
    def _setup_vless_outbound(self, config, node_config):
        """设置VLESS outbound"""
        try:
            parsed = urlparse(node_config)
            hostname = parsed.hostname
            port = parsed.port or 443
            user_id = parsed.username
            
            outbound = {
                "tag": "proxy-out",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": hostname,
                        "port": port,
                        "users": [{
                            "id": user_id,
                            "encryption": "none",
                            "level": 0
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls"
                }
            }
            
            config["outbounds"][0] = outbound
            return config
        except Exception as e:
            print(f"VLESS配置错误: {e}")
            return config
    
    def _setup_trojan_outbound(self, config, node_config):
        """设置Trojan outbound"""
        try:
            parsed = urlparse(node_config)
            hostname = parsed.hostname
            port = parsed.port or 443
            password = parsed.username
            
            outbound = {
                "tag": "proxy-out",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": hostname,
                        "port": port,
                        "password": password
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls"
                }
            }
            
            config["outbounds"][0] = outbound
            return config
        except Exception as e:
            print(f"Trojan配置错误: {e}")
            return config
    
    def _setup_ss_outbound(self, config, node_config):
        """设置Shadowsocks outbound"""
        try:
            # 解析SS链接
            if node_config.startswith('ss://'):
                ss_str = node_config[5:]
                if '#' in ss_str:
                    ss_str = ss_str.split('#')[0]
                
                # 处理base64编码
                if '@' not in ss_str:
                    try:
                        padding = 4 - len(ss_str) % 4
                        if padding != 4:
                            ss_str += '=' * padding
                        decoded = base64.b64decode(ss_str).decode('utf-8')
                        if '@' in decoded:
                            method_password, server = decoded.split('@', 1)
                            if ':' in method_password:
                                method, password = method_password.split(':', 1)
                            else:
                                method, password = "aes-256-gcm", method_password
                            
                            if ':' in server:
                                host, port = server.split(':', 1)
                            else:
                                host, port = server, "8388"
                        else:
                            return config
                    except:
                        return config
                else:
                    # 直接解析
                    method_password, server = ss_str.split('@', 1)
                    if ':' in method_password:
                        method, password = method_password.split(':', 1)
                    else:
                        method, password = "aes-256-gcm", method_password
                    
                    if ':' in server:
                        host, port = server.split(':', 1)
                    else:
                        host, port = server, "8388"
                
                outbound = {
                    "tag": "proxy-out",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": host,
                            "port": int(port),
                            "method": method,
                            "password": password
                        }]
                    }
                }
                
                config["outbounds"][0] = outbound
                return config
            
            return config
        except Exception as e:
            print(f"Shadowsocks配置错误: {e}")
            return config
    
    def test_node_with_xray_debug(self, node_config, config_path):
        """调试版本的Xray测试"""
        try:
            print(f"🔧 启动Xray测试...")
            
            # 启动Xray并捕获输出
            xray_process = subprocess.Popen([
                "xray", "run", "-config", config_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # 等待启动
            time.sleep(3)
            
            # 检查Xray是否在运行
            if xray_process.poll() is not None:
                stdout, stderr = xray_process.communicate()
                print(f"❌ Xray进程已退出")
                print(f"STDERR: {stderr}")
                return False, 0, False, 0
            
            # 测试1: 直接测试SOCKS端口
            print(f"🔌 测试SOCKS5端口连接...")
            socks_success = self.test_socks_connection()
            
            # 测试2: 通过代理测试HTTP
            print(f"🌐 测试HTTP代理连接...")
            http_success, http_latency = self.test_http_via_proxy()
            
            # 测试3: 测试下载速度
            speed_success, speed_mbps = False, 0
            if http_success:
                print(f"📊 测试下载速度...")
                speed_success, speed_mbps = self.test_speed_via_proxy_simple()
            
            # 停止Xray
            xray_process.terminate()
            try:
                xray_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                xray_process.kill()
            
            print(f"📊 测试结果 - SOCKS: {socks_success}, HTTP: {http_success}, 速度: {speed_success}")
            return speed_success, speed_mbps, http_success, http_latency
            
        except Exception as e:
            print(f"❌ Xray测试异常: {e}")
            return False, 0, False, 0
    
    def test_socks_connection(self):
        """测试SOCKS5端口连接"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(('127.0.0.1', 10808))
            sock.close()
            return result == 0
        except:
            return False
    
    def test_http_via_proxy(self):
        """通过代理测试HTTP连接"""
        try:
            proxies = {
                'http': 'socks5://127.0.0.1:10808',
                'https': 'socks5://127.0.0.1:10808'
            }
            
            session = requests.Session()
            session.verify = False
            session.proxies = proxies
            
            start_time = time.time()
            response = session.get('http://httpbin.org/get', timeout=10)
            latency = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                return True, latency
            return False, 0
        except Exception as e:
            print(f"HTTP代理测试失败: {e}")
            return False, 0
    
    def test_speed_via_proxy_simple(self):
        """简化速度测试"""
        try:
            proxies = {
                'http': 'socks5://127.0.0.1:10808',
                'https': 'socks5://127.0.0.1:10808'
            }
            
            session = requests.Session()
            session.verify = False
            session.proxies = proxies
            
            start_time = time.time()
            response = session.get('http://httpbin.org/bytes/100000', timeout=10, stream=True)
            
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size >= 50000:  # 50KB即可
                    break
            
            download_time = time.time() - start_time
            if download_time > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                return True, speed_mbps
            return False, 0
        except Exception as e:
            print(f"速度测试失败: {e}")
            return False, 0
    
    def test_single_node(self, node, index):
        """测试单个节点"""
        config = node['config']
        original_config = node['original_config']
        
        host, port = self.extract_server_info(config)
        
        if not host:
            print(f"❌ 节点 {index}: 解析失败")
            return None
        
        print(f"\n🔍 测试节点 {index}: {host}:{port}")
        
        # 1. 基础连通性测试
        ping_success, ping_latency = self.test_icmp_ping(host)
        tcp_success, tcp_latency = self.test_tcp_connect(host, port)
        
        print(f"   Ping: {'✅' if ping_success else '❌'} {ping_latency or '失败'}")
        print(f"   TCP: {'✅' if tcp_success else '❌'} {tcp_latency or '失败'}")
        
        # 2. Xray代理测试
        speed_success, speed_mbps, tls_success, tls_latency = False, 0, False, 0
        
        if tcp_success:  # 只有TCP通才测试代理
            config_path = os.path.join(self.xray_config_dir, f"config_{index}.json")
            if self.create_simple_xray_config(original_config, config_path):
                speed_success, speed_mbps, tls_success, tls_latency = self.test_node_with_xray_debug(original_config, config_path)
        
        print(f"   代理测试: 速度{'✅' if speed_success else '❌'} {speed_mbps:.2f}Mbps, "
              f"HTTP{'✅' if tls_success else '❌'} {tls_latency or '失败'}ms")
        
        return {
            'original_config': original_config,
            'tcp_success': tcp_success,
            'speed_success': speed_success,
            'tls_success': tls_success
        }
    
    def run_comprehensive_test(self):
        """运行测试"""
        nodes = self.read_nodes()
        if not nodes:
            return
        
        print(f"\n🚀 开始测试 {len(nodes)} 个节点...")
        
        valid_nodes = []
        
        for i, node in enumerate(nodes, 1):
            result = self.test_single_node(node, i)
            if result and result.get('tcp_success') and result.get('speed_success') and result.get('tls_success'):
                valid_nodes.append(result['original_config'])
                print(f"   ✅ 节点合格")
            else:
                print(f"   ❌ 节点不合格")
            
            time.sleep(1)
        
        # 保存结果
        if valid_nodes:
            with open('ping.txt', 'w', encoding='utf-8') as f:
                for config in valid_nodes:
                    f.write(config + '\n')
            print(f"\n💾 保存 {len(valid_nodes)} 个有效节点")
        else:
            print(f"\n⚠️  没有找到有效节点")
        
        print(f"\n📊 测试完成: 总共{len(nodes)}节点，有效{len(valid_nodes)}节点")


def main():
    """主函数"""
    if not os.path.exists("ping.txt"):
        print("❌ 找不到 ping.txt")
        return
    
    # 检查环境
    try:
        result = subprocess.run(["xray", "version"], capture_output=True, text=True)
        print(f"✅ Xray版本: {result.stdout.strip()}")
    except:
        print("❌ Xray未安装或不可用")
        return
    
    tester = XrayNodeTester(
        enable_ping=False,
        enable_tcp=True, 
        enable_speedtest=True,
        enable_tls_http_test=True
    )
    
    try:
        start_time = time.time()
        tester.run_comprehensive_test()
        end_time = time.time()
        print(f"\n⏱️  总耗时: {end_time - start_time:.2f}秒")
    except Exception as e:
        print(f"❌ 测试错误: {e}")


if __name__ == "__main__":
    main()
