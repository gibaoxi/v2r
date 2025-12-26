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

class NodeConnectivityTester:
    def __init__(self, enable_ping=True, enable_tcp=True, enable_speedtest=True, enable_tls_http_test=True):
        self.sub_file = "ping.txt"
        self.ping_timeout = 3
        self.tcp_timeout = 5
        self.speedtest_timeout = 15  # 增加超时时间
        self.tls_http_timeout = 8
        self.enable_ping = enable_ping
        self.enable_tcp = enable_tcp
        self.enable_speedtest = enable_speedtest
        self.enable_tls_http_test = enable_tls_http_test
        
        # 速度测试配置 - 使用小文件测试
        self.speedtest_files = [
            "https://speed.cloudflare.com/__down?bytes=1000000",  # 1MB
            "http://httpbin.org/bytes/500000",  # 500KB
            "https://httpbin.org/bytes/500000",  # 500KB
        ]
        
        # TLS/HTTP测试配置
        self.tls_test_sites = [
            "https://www.google.com",
            "https://www.github.com", 
            "https://www.cloudflare.com",
            "https://www.baidu.com",
        ]
        
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
        """从节点配置提取服务器地址和端口"""
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
            if os.name == 'nt':
                cmd = ['ping', '-n', '3', '-w', str(self.ping_timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '3', '-W', str(self.ping_timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.ping_timeout + 2)
            
            if result.returncode == 0:
                output = result.stdout
                if 'avg' in output:
                    match = re.search(r'(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', output)
                    if match:
                        return True, float(match.group(2))
                elif 'Average' in output:
                    match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        return True, float(match.group(1))
            
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
    
    def setup_proxy_from_config(self, node_config):
        """根据节点配置设置代理"""
        try:
            if node_config.startswith('vmess://'):
                # 简化处理：对于VMess等复杂协议，直接返回None，使用直接连接
                return None
            elif node_config.startswith('http://') or node_config.startswith('https://'):
                # HTTP代理
                return {
                    'http': node_config,
                    'https': node_config
                }
            elif node_config.startswith('socks5://') or node_config.startswith('socks4://'):
                # SOCKS代理
                return {
                    'http': node_config,
                    'https': node_config
                }
            else:
                # 其他协议暂不支持代理测试
                return None
        except Exception:
            return None
    
    def test_download_speed_via_proxy(self, node_config):
        """通过节点代理测试下载速度"""
        if not self.enable_speedtest:
            return False, 0, 0
            
        try:
            # 设置代理
            proxies = self.setup_proxy_from_config(node_config)
            
            if proxies is None:
                # 如果不支持代理测试，使用直接连接
                return self.test_download_speed_direct()
            
            test_url = self.speedtest_files[0]
            start_time = time.time()
            
            # 使用session来复用连接
            session = requests.Session()
            session.verify = False  # 禁用证书验证
            session.proxies = proxies
            
            response = session.get(test_url, timeout=self.speedtest_timeout, stream=True)
            
            total_size = 0
            chunk_size = 8192  # 8KB
            
            for chunk in response.iter_content(chunk_size=chunk_size):
                total_size += len(chunk)
                elapsed = time.time() - start_time
                
                if elapsed > self.speedtest_timeout:
                    break
                    
                # 下载1MB数据就足够测试速度
                if total_size > 1 * 1024 * 1024:
                    break
            
            end_time = time.time()
            download_time = end_time - start_time
            
            if download_time > 0 and total_size > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                speed_mbs = total_size / (download_time * 1024 * 1024)
                return True, speed_mbps, speed_mbs
            else:
                return False, 0, 0
                
        except Exception as e:
            print(f"    代理下载错误: {e}")
            return False, 0, 0
    
    def test_download_speed_direct(self):
        """直接下载速度测试（备用）"""
        try:
            test_url = self.speedtest_files[1]  # 使用较小的文件
            start_time = time.time()
            
            session = requests.Session()
            session.verify = False
            response = session.get(test_url, timeout=10, stream=True)
            
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if time.time() - start_time > 10:
                    break
                if total_size > 500000:  # 500KB
                    break
            
            download_time = time.time() - start_time
            if download_time > 0 and total_size > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                return True, speed_mbps, speed_mbps / 8
            return False, 0, 0
        except Exception:
            return False, 0, 0

    def test_tls_http_connectivity(self, host):
        """测试节点是否能完成TLS/HTTP连接"""
        if not self.enable_tls_http_test:
            return False, 0, "disabled"
            
        try:
            success_count = 0
            total_tests = 0
            best_latency = float('inf')
            protocols = []
            
            session = requests.Session()
            session.verify = False
            
            for test_url in self.tls_test_sites:
                try:
                    total_tests += 1
                    start_time = time.time()
                    
                    response = session.get(test_url, timeout=self.tls_http_timeout)
                    latency = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        success_count += 1
                        if latency < best_latency:
                            best_latency = latency
                        
                        if response.url.startswith('https://'):
                            protocols.append('TLS/HTTPS')
                        else:
                            protocols.append('HTTP')
                    
                    response.close()
                    
                except requests.exceptions.SSLError:
                    protocols.append('TLS_Failed')
                except requests.exceptions.ConnectTimeout:
                    protocols.append('Timeout')
                except requests.exceptions.ConnectionError:
                    protocols.append('ConnectionError')
                except Exception:
                    protocols.append('OtherError')
            
            if success_count > 0:
                success_rate = (success_count / total_tests) * 100
                
                if 'TLS/HTTPS' in protocols:
                    protocol = 'TLS/HTTPS'
                elif 'HTTP' in protocols:
                    protocol = 'HTTP'
                else:
                    protocol = 'Failed'
                
                return True, best_latency, f"{protocol}({success_rate:.1f}%)"
            else:
                return False, 0, "AllFailed"
                
        except Exception:
            return False, 0, "Error"
    
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
                'speed_mbs': 0,
                'tls_http_success': False,
                'tls_http_latency': 0,
                'tls_http_protocol': ''
            }
        
        print(f"测试节点 {index}: {host}" + (f":{port}" if port else ""))
        
        # 测试ICMP ping
        ping_success, ping_latency = False, None
        if self.enable_ping:
            ping_success, ping_latency = self.test_icmp_ping(host)
            if ping_success:
                print(f"  Ping: {ping_latency:.1f}ms")
            else:
                print(f"  Ping: 失败")
        
        # 测试TCP端口连接
        tcp_success, tcp_latency = False, None
        if self.enable_tcp and port:
            tcp_success, tcp_latency = self.test_tcp_connect(host, port)
            if tcp_success:
                print(f"  TCP: {tcp_latency:.1f}ms")
            else:
                print(f"  TCP: 失败")
        
        # 测试下载速度（通过代理）
        speed_success, speed_mbps, speed_mbs = False, 0, 0
        if self.enable_speedtest:
            speed_success, speed_mbps, speed_mbs = self.test_download_speed_via_proxy(original_config)
            if speed_success:
                print(f"  代理下载速度: {speed_mbps:.2f} Mbps")
            else:
                print(f"  代理下载速度: 失败")
        
        # 测试TLS/HTTP连接性
        tls_http_success, tls_http_latency, tls_http_protocol = False, 0, ""
        if self.enable_tls_http_test:
            tls_http_success, tls_http_latency, tls_http_protocol = self.test_tls_http_connectivity(host)
            if tls_http_success:
                print(f"  TLS/HTTP: {tls_http_latency:.1f}ms ({tls_http_protocol})")
            else:
                print(f"  TLS/HTTP: 失败 ({tls_http_protocol})")
        
        # 统计成功测试数量
        success_count = 0
        total_tests = 0
        
        if self.enable_ping:
            total_tests += 1
            if ping_success:
                success_count += 1
                
        if self.enable_tcp and port:
            total_tests += 1
            if tcp_success:
                success_count += 1
                
        if self.enable_speedtest:
            total_tests += 1
            if speed_success:
                success_count += 1
                
        if self.enable_tls_http_test:
            total_tests += 1
            if tls_http_success:
                success_count += 1
        
        # 确定状态
        if total_tests == 0:
            status = 'all_disabled'
        elif success_count == total_tests:
            status = 'all_success'
        elif success_count > 0:
            status = 'partial_success'
        else:
            status = 'all_failed'
        
        return {
            'index': index,
            'original_config': original_config,
            'host': host,
            'port': port,
            'status': status,
            'ping_success': ping_success,
            'ping_latency': ping_latency,
            'tcp_success': tcp_success,
            'tcp_latency': tcp_latency,
            'speed_success': speed_success,
            'speed_mbps': speed_mbps,
            'speed_mbs': speed_mbs,
            'tls_http_success': tls_http_success,
            'tls_http_latency': tls_http_latency,
            'tls_http_protocol': tls_http_protocol,
            'success_count': success_count,
            'total_tests': total_tests
        }
    
    def run_comprehensive_test(self):
        """运行综合测试"""
        print("=" * 50)
        print("节点连通性测试")
        print("=" * 50)
        print(f"Ping测试: {'启用' if self.enable_ping else '禁用'}")
        print(f"TCP测试: {'启用' if self.enable_tcp else '禁用'}")
        print(f"速度测试: {'启用' if self.enable_speedtest else '禁用'} (通过代理)")
        print(f"TLS/HTTP测试: {'启用' if self.enable_tls_http_test else '禁用'}")
        print("=" * 50)
        
        nodes = self.read_nodes()
        if not nodes:
            return
        
        print(f"开始测试 {len(nodes)} 个节点...")
        
        results = []
        valid_nodes = []
        
        for i, node in enumerate(nodes, 1):
            result = self.test_single_node(node, i)
            results.append(result)
            
            if result['success_count'] > 0:
                valid_nodes.append(result['original_config'])
            
            time.sleep(0.5)
        
        # 保存有效节点
        if valid_nodes:
            with open('ping.txt', 'w', encoding='utf-8') as f:
                for config in valid_nodes:
                    f.write(config + '\n')
            print(f"\n保存 {len(valid_nodes)} 个有效节点到 ping.txt")
        else:
            print("\n没有找到有效节点")
        
        # 显示统计信息
        total = len(results)
        valid_count = len(valid_nodes)
        failed_count = total - valid_count
        
        print(f"\n测试完成:")
        print(f"总节点: {total}")
        print(f"有效节点: {valid_count}")
        print(f"失败节点: {failed_count}")
        
        return results


def main():
    """主函数"""
    if not os.path.exists("ping.txt"):
        print(f"错误: 找不到 ping.txt 文件")
        return
    
    # 配置测试开关
    enable_ping = True
    enable_tcp = True
    enable_speedtest = True
    enable_tls_http_test = True
    
    # 创建测试器
    tester = NodeConnectivityTester(
        enable_ping=enable_ping, 
        enable_tcp=enable_tcp, 
        enable_speedtest=enable_speedtest,
        enable_tls_http_test=enable_tls_http_test
    )
    
    # 运行测试
    try:
        start_time = time.time()
        results = tester.run_comprehensive_test()
        end_time = time.time()
        
        if results:
            print(f"\n总耗时: {end_time - start_time:.2f} 秒")
        
    except KeyboardInterrupt:
        print("\n测试被用户中断")
    except Exception as e:
        print(f"\n测试错误: {e}")


if __name__ == "__main__":
    main()
