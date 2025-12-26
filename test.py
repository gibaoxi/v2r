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

# 抑制SSL证书警告
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
        
        # 创建配置目录
        os.makedirs(self.xray_config_dir, exist_ok=True)
        
        # 测试配置
        self.speedtest_files = [
            "https://speed.cloudflare.com/__down?bytes=1000000",
            "https://proof.ovh.net/files/10Mb.dat",
        ]
        
        self.tls_test_sites = [
            "https://www.google.com",
            "https://www.github.com", 
            "https://www.cloudflare.com",
        ]
        
        print("=" * 60)
        print("Xray节点测试 (GitHub Actions)")
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
        """从节点配置提取服务器信息"""
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
                    
        except Exception:
            pass
            
        return None, None
    
    def test_icmp_ping(self, host):
        """测试ICMP ping"""
        if not self.enable_ping:
            return False, None
            
        try:
            cmd = ['ping', '-c', '3', '-W', str(self.ping_timeout), host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.ping_timeout + 2)
            
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
        """测试TCP端口连接"""
        if not self.enable_tcp:
            return False, None
            
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tcp_timeout)
            result = sock.connect_ex((host, int(port)))
            latency = (time.time() - start_time) * 1000
            sock.close()
            
            return result == 0, latency
        except:
            return False, None
    
    def create_xray_config(self, node_config, config_path):
        """创建Xray配置文件"""
        try:
            if node_config.startswith('vmess://'):
                return self._create_vmess_config(node_config, config_path)
            elif node_config.startswith('vless://'):
                return self._create_vless_config(node_config, config_path)
            elif node_config.startswith('trojan://'):
                return self._create_trojan_config(node_config, config_path)
            elif node_config.startswith('ss://'):
                return self._create_ss_config(node_config, config_path)
            else:
                return False
        except Exception as e:
            print(f"创建Xray配置失败: {e}")
            return False
    
    def _create_vmess_config(self, node_config, config_path):
        """创建VMess配置"""
        try:
            encoded = node_config[8:]
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            decoded = base64.b64decode(encoded).decode('utf-8')
            vmess_config = json.loads(decoded)
            
            config = {
                "inbounds": [{
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }],
                "outbounds": [{
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": vmess_config.get("add"),
                            "port": int(vmess_config.get("port", 443)),
                            "users": [{
                                "id": vmess_config.get("id"),
                                "alterId": int(vmess_config.get("aid", 0))
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": vmess_config.get("net", "tcp"),
                        "security": vmess_config.get("tls", "")
                    }
                }]
            }
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception:
            return False
    
    def _create_vless_config(self, node_config, config_path):
        """创建VLESS配置"""
        try:
            parsed = urlparse(node_config)
            hostname = parsed.hostname
            port = parsed.port or 443
            user_id = parsed.username
            path = parsed.path or ""
            query_params = parsed.query
            
            config = {
                "inbounds": [{
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": hostname,
                            "port": port,
                            "users": [{
                                "id": user_id,
                                "encryption": "none"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls"
                    }
                }]
            }
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception:
            return False
    
    def _create_trojan_config(self, node_config, config_path):
        """创建Trojan配置"""
        try:
            parsed = urlparse(node_config)
            hostname = parsed.hostname
            port = parsed.port or 443
            password = parsed.username
            
            config = {
                "inbounds": [{
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }],
                "outbounds": [{
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
                }]
            }
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception:
            return False
    
    def _create_ss_config(self, node_config, config_path):
        """创建Shadowsocks配置"""
        try:
            # 解析SS链接格式: ss://method:password@host:port
            if node_config.startswith('ss://'):
                # 移除ss://前缀
                ss_str = node_config[5:]
                
                # 处理base64编码的情况
                if '#' in ss_str:
                    ss_str = ss_str.split('#')[0]
                
                # 如果是base64编码，解码
                if '@' not in ss_str and ':' in ss_str:
                    try:
                        padding = 4 - len(ss_str) % 4
                        if padding != 4:
                            ss_str += '=' * padding
                        decoded = base64.b64decode(ss_str).decode('utf-8')
                        # decoded格式: method:password@host:port
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
                            return False
                    except:
                        return False
                else:
                    # 直接解析
                    if '@' in ss_str:
                        method_password, server = ss_str.split('@', 1)
                        if ':' in method_password:
                            method, password = method_password.split(':', 1)
                        else:
                            method, password = "aes-256-gcm", method_password
                        
                        if ':' in server:
                            host, port = server.split(':', 1)
                        else:
                            host, port = server, "8388"
                    else:
                        return False
                
                config = {
                    "inbounds": [{
                        "port": 1080,
                        "listen": "127.0.0.1",
                        "protocol": "socks",
                        "settings": {
                            "auth": "noauth",
                            "udp": True
                        }
                    }],
                    "outbounds": [{
                        "protocol": "shadowsocks",
                        "settings": {
                            "servers": [{
                                "address": host,
                                "port": int(port),
                                "method": method,
                                "password": password
                            }]
                        }
                    }]
                }
                
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                return True
            
            return False
        except Exception:
            return False
    
    def test_node_with_xray(self, node_config, config_path):
        """使用Xray测试节点"""
        try:
            # 启动Xray
            xray_process = subprocess.Popen([
                "xray", "run", "-config", config_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # 等待Xray启动
            time.sleep(2)
            
            # 测试代理连接
            proxies = {
                'http': 'socks5://127.0.0.1:1080',
                'https': 'socks5://127.0.0.1:1080'
            }
            
            # 测试下载速度
            speed_success, speed_mbps = self._test_speed_via_proxy(proxies)
            
            # 测试TLS连接
            tls_success, tls_latency = self._test_tls_via_proxy(proxies)
            
            # 停止Xray
            xray_process.terminate()
            xray_process.wait()
            
            return speed_success, speed_mbps, tls_success, tls_latency
            
        except Exception as e:
            print(f"Xray测试失败: {e}")
            return False, 0, False, 0
    
    def _test_speed_via_proxy(self, proxies):
        """通过代理测试速度"""
        try:
            test_url = self.speedtest_files[0]
            session = requests.Session()
            session.verify = False
            session.proxies = proxies
            
            start_time = time.time()
            response = session.get(test_url, timeout=self.speedtest_timeout, stream=True)
            
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if time.time() - start_time > 10:  # 最多测试10秒
                    break
                if total_size > 500000:  # 下载500KB
                    break
            
            download_time = time.time() - start_time
            if download_time > 0 and total_size > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                return True, speed_mbps
            return False, 0
        except Exception:
            return False, 0
    
    def _test_tls_via_proxy(self, proxies):
        """通过代理测试TLS"""
        try:
            session = requests.Session()
            session.verify = False
            session.proxies = proxies
            
            best_latency = float('inf')
            success_count = 0
            
            for test_url in self.tls_test_sites:
                try:
                    start_time = time.time()
                    response = session.get(test_url, timeout=self.tls_http_timeout)
                    latency = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        success_count += 1
                        if latency < best_latency:
                            best_latency = latency
                    response.close()
                except:
                    continue
            
            return success_count > 0, best_latency
        except Exception:
            return False, 0
    
    def test_single_node(self, node, index):
        """测试单个节点"""
        config = node['config']
        original_config = node['original_config']
        
        host, port = self.extract_server_info(config)
        
        if not host:
            return {
                'index': index,
                'original_config': original_config,
                'status': 'parse_error',
                'host': None,
                'port': None,
                'ping_success': False,
                'ping_latency': None,
                'tcp_success': False,
                'tcp_latency': None,
                'speed_success': False,
                'speed_mbps': 0,
                'tls_success': False,
                'tls_latency': 0
            }
        
        print(f"\n测试节点 {index}: {host}" + (f":{port}" if port else ""))
        
        # 1. 测试Ping
        ping_success, ping_latency = False, None
        if self.enable_ping:
            ping_success, ping_latency = self.test_icmp_ping(host)
            if ping_success:
                print(f"  Ping: ✅ {ping_latency:.1f}ms")
            else:
                print(f"  Ping: ❌ 失败")
        
        # 2. 测试TCP
        tcp_success, tcp_latency = False, None
        if self.enable_tcp and port:
            tcp_success, tcp_latency = self.test_tcp_connect(host, port)
            if tcp_success:
                print(f"  TCP: ✅ {tcp_latency:.1f}ms")
            else:
                print(f"  TCP: ❌ 失败")
        
        # 3. 使用Xray测试代理功能
        speed_success, speed_mbps, tls_success, tls_latency = False, 0, False, 0
        if self.enable_speedtest or self.enable_tls_http_test:
            config_path = os.path.join(self.xray_config_dir, f"config_{index}.json")
            
            if self.create_xray_config(original_config, config_path):
                print(f"  Xray测试: 启动中...")
                speed_success, speed_mbps, tls_success, tls_latency = self.test_node_with_xray(original_config, config_path)
                
                if speed_success:
                    print(f"  速度(Xray): ✅ {speed_mbps:.2f} Mbps")
                else:
                    print(f"  速度(Xray): ❌ 失败")
                    
                if tls_success:
                    print(f"  TLS(Xray): ✅ {tls_latency:.1f}ms")
                else:
                    print(f"  TLS(Xray): ❌ 失败")
            else:
                print(f"  Xray测试: ❌ 配置创建失败")
        
        return {
            'index': index,
            'original_config': original_config,
            'host': host,
            'port': port,
            'ping_success': ping_success,
            'ping_latency': ping_latency,
            'tcp_success': tcp_success,
            'tcp_latency': tcp_latency,
            'speed_success': speed_success,
            'speed_mbps': speed_mbps,
            'tls_success': tls_success,
            'tls_latency': tls_latency
        }
    
    def run_comprehensive_test(self):
        """运行综合测试"""
        nodes = self.read_nodes()
        if not nodes:
            return
        
        print(f"\n开始测试 {len(nodes)} 个节点...")
        print("使用Xray进行代理功能测试")
        print("=" * 50)
        
        valid_nodes = []
        
        for i, node in enumerate(nodes, 1):
            result = self.test_single_node(node, i)
            
            # 检查条件
            tcp_ok = result.get('tcp_success', False)
            speed_ok = result.get('speed_success', False)
            tls_ok = result.get('tls_success', False)
            
            if tcp_ok and speed_ok and tls_ok:
                valid_nodes.append(result['original_config'])
                print(f"  ✅ 节点满足所有条件")
            else:
                missing = []
                if not tcp_ok: missing.append("TCP")
                if not speed_ok: missing.append("速度")
                if not tls_ok: missing.append("TLS")
                print(f"  ❌ 缺少: {', '.join(missing)}")
            
            time.sleep(1)
        
        # 保存结果
        if valid_nodes:
            with open('ping.txt', 'w', encoding='utf-8') as f:
                for config in valid_nodes:
                    f.write(config + '\n')
            print(f"\n保存 {len(valid_nodes)} 个有效节点")
        else:
            print("\n没有有效节点")
        
        print(f"\n测试完成: 总共{len(nodes)}节点，有效{len(valid_nodes)}节点")


def main():
    """主函数"""
    if not os.path.exists("ping.txt"):
        print("错误: 找不到 ping.txt")
        return
    
    # 检查Xray是否可用
    try:
        subprocess.run(["xray", "version"], capture_output=True, check=True)
        print("✅ Xray可用")
    except:
        print("❌ Xray不可用，将使用简化测试")
        # 可以回退到之前的测试方法
        return
    
    tester = XrayNodeTester(
        enable_ping=True,
        enable_tcp=True, 
        enable_speedtest=True,
        enable_tls_http_test=True
    )
    
    try:
        start_time = time.time()
        tester.run_comprehensive_test()
        end_time = time.time()
        print(f"\n总耗时: {end_time - start_time:.2f}秒")
    except Exception as e:
        print(f"测试错误: {e}")


if __name__ == "__main__":
    main()
