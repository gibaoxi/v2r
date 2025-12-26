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
        self.speedtest_timeout = 15
        self.tls_http_timeout = 8
        self.enable_ping = enable_ping
        self.enable_tcp = enable_tcp
        self.enable_speedtest = enable_speedtest
        self.enable_tls_http_test = enable_tls_http_test
        
        # 测试说明
        print("=" * 60)
        print("节点连通性测试说明:")
        print("- Ping/TCP测试: 测试本地到节点服务器的连接")
        print("- 速度/TLS测试: 测试节点代理到目标网站的能力") 
        print("- 保存条件: 必须同时满足 TCP连接 + 下载测试 + TLS测试 三个条件")
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
        """测试本地到节点服务器的ICMP ping"""
        if not self.enable_ping:
            return False, None, "本地→节点"
            
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
                        return True, float(match.group(2)), "本地→节点"
                elif 'Average' in output:
                    match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        return True, float(match.group(1)), "本地→节点"
            
            return False, None, "本地→节点"
            
        except Exception:
            return False, None, "本地→节点"
    
    def test_tcp_connect(self, host, port):
        """测试本地到节点服务器的TCP连接"""
        if not self.enable_tcp:
            return False, None, "本地→节点"
            
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tcp_timeout)
            result = sock.connect_ex((host, int(port)))
            latency = (time.time() - start_time) * 1000
            sock.close()
            
            return result == 0, latency, "本地→节点"
        except:
            return False, None, "本地→节点"
    
    def test_proxy_download_speed(self, node_config):
        """测试通过节点代理的下载速度"""
        if not self.enable_speedtest:
            return False, 0, 0, "节点→目标"
            
        try:
            # 设置代理
            proxies = self._setup_proxy(node_config)
            if not proxies:
                return False, 0, 0, "节点→目标"
            
            test_url = "https://speed.cloudflare.com/__down?bytes=1000000"  # 1MB
            
            session = requests.Session()
            session.verify = False
            session.proxies = proxies
            
            start_time = time.time()
            response = session.get(test_url, timeout=self.speedtest_timeout, stream=True)
            
            total_size = 0
            chunk_size = 8192
            
            for chunk in response.iter_content(chunk_size=chunk_size):
                total_size += len(chunk)
                if time.time() - start_time > self.speedtest_timeout:
                    break
                if total_size > 500000:  # 下载500KB即可
                    break
            
            download_time = time.time() - start_time
            
            if download_time > 0 and total_size > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                return True, speed_mbps, speed_mbps/8, "节点→目标"
            return False, 0, 0, "节点→目标"
            
        except Exception as e:
            return False, 0, 0, f"节点→目标: {str(e)[:30]}"
    
    def test_proxy_tls_http(self, node_config):
        """测试通过节点代理的TLS/HTTP连接"""
        if not self.enable_tls_http_test:
            return False, 0, "disabled", "节点→目标"
            
        try:
            proxies = self._setup_proxy(node_config)
            if not proxies:
                return False, 0, "无代理", "节点→目标"
            
            test_sites = [
                "https://www.google.com",
                "https://www.github.com",
                "https://www.cloudflare.com"
            ]
            
            session = requests.Session()
            session.verify = False
            session.proxies = proxies
            
            success_count = 0
            best_latency = float('inf')
            
            for test_url in test_sites:
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
            
            if success_count > 0:
                success_rate = (success_count / len(test_sites)) * 100
                return True, best_latency, f"成功{success_count}/{len(test_sites)}", "节点→目标"
            else:
                return False, 0, "全部失败", "节点→目标"
                
        except Exception as e:
            return False, 0, f"错误: {str(e)[:30]}", "节点→目标"
    
    def _setup_proxy(self, node_config):
        """设置代理配置"""
        try:
            # 简化代理设置，实际使用时需要根据协议类型具体实现
            if node_config.startswith('http://') or node_config.startswith('https://'):
                return {'http': node_config, 'https': node_config}
            elif node_config.startswith('socks'):
                return {'http': node_config, 'https': node_config}
            else:
                # 对于VMess等复杂协议，返回None表示不支持代理测试
                return None
        except:
            return None
    
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
                'tls_success': False,
                'tls_latency': 0,
                'tls_info': ""
            }
        
        print(f"\n测试节点 {index}: {host}" + (f":{port}" if port else ""))
        
        # 1. 测试本地到节点的Ping
        ping_success, ping_latency, ping_desc = False, None, ""
        if self.enable_ping:
            ping_success, ping_latency, ping_desc = self.test_icmp_ping(host)
            status = "✅" if ping_success else "❌"
            latency_info = f"{ping_latency:.1f}ms" if ping_latency else "失败"
            print(f"  Ping({ping_desc}): {status} {latency_info}")
        
        # 2. 测试本地到节点的TCP
        tcp_success, tcp_latency, tcp_desc = False, None, ""
        if self.enable_tcp and port:
            tcp_success, tcp_latency, tcp_desc = self.test_tcp_connect(host, port)
            status = "✅" if tcp_success else "❌"
            latency_info = f"{tcp_latency:.1f}ms" if tcp_latency else "失败"
            print(f"  TCP({tcp_desc}): {status} {latency_info}")
        
        # 3. 测试通过节点的下载速度
        speed_success, speed_mbps, speed_mbs, speed_desc = False, 0, 0, ""
        if self.enable_speedtest:
            speed_success, speed_mbps, speed_mbs, speed_desc = self.test_proxy_download_speed(original_config)
            status = "✅" if speed_success else "❌"
            speed_info = f"{speed_mbps:.2f}Mbps" if speed_success else "失败"
            print(f"  速度({speed_desc}): {status} {speed_info}")
        
        # 4. 测试通过节点的TLS/HTTP
        tls_success, tls_latency, tls_info, tls_desc = False, 0, "", ""
        if self.enable_tls_http_test:
            tls_success, tls_latency, tls_info, tls_desc = self.test_proxy_tls_http(original_config)
            status = "✅" if tls_success else "❌"
            latency_info = f"{tls_latency:.1f}ms" if tls_success else "失败"
            print(f"  TLS({tls_desc}): {status} {latency_info} {tls_info}")
        
        # 统计结果
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
            'tls_latency': tls_latency,
            'tls_info': tls_info
        }
    
    def run_comprehensive_test(self):
        """运行综合测试"""
        nodes = self.read_nodes()
        if not nodes:
            return
        
        print(f"\n开始测试 {len(nodes)} 个节点...")
        print("筛选条件: 必须同时满足 TCP连接 + 下载测试 + TLS测试 三个条件")
        
        valid_nodes = []
        
        for i, node in enumerate(nodes, 1):
            result = self.test_single_node(node, i)
            
            # 检查三个条件是否都满足
            tcp_ok = result.get('tcp_success', False)
            speed_ok = result.get('speed_success', False)
            tls_ok = result.get('tls_success', False)
            
            if tcp_ok and speed_ok and tls_ok:
                valid_nodes.append(result['original_config'])
                print(f"  ✅ 节点满足所有条件，已保存")
            else:
                # 显示具体哪些条件不满足
                missing = []
                if not tcp_ok: missing.append("TCP")
                if not speed_ok: missing.append("下载")
                if not tls_ok: missing.append("TLS")
                print(f"  ❌ 缺少条件: {', '.join(missing)}")
            
            time.sleep(1)
        
        # 保存有效节点
        if valid_nodes:
            with open('ping.txt', 'w', encoding='utf-8') as f:
                for config in valid_nodes:
                    f.write(config + '\n')
            print(f"\n保存 {len(valid_nodes)} 个有效节点到 ping.txt")
            print("这些节点同时满足: TCP连接成功 + 下载测试成功 + TLS测试成功")
        else:
            print("\n没有找到同时满足三个条件的节点")
        
        # 显示统计信息
        total = len(nodes)
        valid_count = len(valid_nodes)
        failed_count = total - valid_count
        
        print(f"\n测试完成:")
        print(f"总节点: {total}")
        print(f"有效节点: {valid_count} (同时满足三个条件)")
        print(f"不满足节点: {failed_count}")
        
        return valid_nodes


def main():
    """主函数"""
    if not os.path.exists("ping.txt"):
        print("错误: 找不到 ping.txt 文件")
        return
    
    tester = NodeConnectivityTester(
        enable_ping=True,
        enable_tcp=True, 
        enable_speedtest=True,
        enable_tls_http_test=True
    )
    
    try:
        start_time = time.time()
        results = tester.run_comprehensive_test()
        end_time = time.time()
        print(f"\n总耗时: {end_time - start_time:.2f}秒")
        
    except Exception as e:
        print(f"测试错误: {e}")


if __name__ == "__main__":
    main()