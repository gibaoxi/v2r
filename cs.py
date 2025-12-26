#!/usr/bin/env python3
import os
import time
import socket
import subprocess
import json
import re
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class NodeConnectivityTester:
    def __init__(self, enable_ping=True, enable_tcp=True, enable_speedtest=True, enable_url_test=True):
        self.sub_file = "ping.txt"
        self.ping_timeout = 3
        self.tcp_timeout = 5
        self.speedtest_timeout = 10
        self.url_test_timeout = 8
        self.max_workers = 3
        self.enable_ping = enable_ping  # Ping控制开关
        self.enable_tcp = enable_tcp    # TCP控制开关
        self.enable_speedtest = enable_speedtest  # 速度测试开关
        self.enable_url_test = enable_url_test  # URL延迟测试开关
        
        # 速度测试配置
        self.speedtest_files = [
            "https://speed.cloudflare.com/__down?bytes=10000000",  # 10MB
            "https://proof.ovh.net/files/10Mb.dat",  # 10MB测试文件
            "https://dl.google.com/dl/android/studio/install/3.6.1.0/android-studio-ide-192.6241897-windows.exe"  # 大文件
        ]
        
        # URL延迟测试配置
        self.url_test_sites = [
            "https://www.google.com",
            "https://www.github.com", 
            "https://www.cloudflare.com",
            "https://www.baidu.com"
        ]
        
    def read_nodes(self):
        """读取节点配置"""
        if not os.path.exists(self.sub_file):
            print(f"❌❌❌❌❌❌❌❌ 错误: 找不到 {self.sub_file}")
            return []
            
        nodes = []
        with open(self.sub_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    nodes.append({
                        'line_num': line_num,
                        'config': clean_line,
                        'original_config': clean_line  # 保存原始配置
                    })
        
        print(f"✅ 成功读取 {len(nodes)} 个节点")
        return nodes
    
    def extract_server_info(self, node_config):
        """从节点配置提取服务器地址和端口"""
        try:
            if node_config.startswith('vmess://'):
                # 解析VMess配置
                import base64
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
                # Shadowsocks格式
                if '@' in node_config:
                    host_port = node_config.split('@')[1].split('#')[0]
                    if ':' in host_port:
                        host, port = host_port.split(':')
                        return host, int(port)
                return None, None
                
            else:
                # 尝试提取IP:PORT格式
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', node_config)
                if match:
                    return match.group(1), int(match.group(2))
                    
        except Exception as e:
            print(f"解析错误: {e}")
            
        return None, None
    
    def test_icmp_ping(self, host):
        """测试ICMP ping"""
        if not self.enable_ping:
            return False, None  # 如果禁用ping，直接返回失败
            
        try:
            # 使用ping命令测试
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '3', '-w', str(self.ping_timeout * 1000), host]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '3', '-W', str(self.ping_timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.ping_timeout + 2)
            
            if result.returncode == 0:
                # 解析ping结果获取平均延迟
                output = result.stdout
                if 'avg' in output:
                    # Linux格式: rtt min/avg/max/mdev = 10.123/15.456/20.789/5.123 ms
                    match = re.search(r'(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', output)
                    if match:
                        return True, float(match.group(2))  # 返回平均延迟
                elif 'Average' in output:
                    # Windows格式: Average = 15ms
                    match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        return True, float(match.group(1))
            
            return False, None
            
        except subprocess.TimeoutExpired:
            return False, None
        except Exception as e:
            return False, None
    
    def test_tcp_connect(self, host, port):
        """测试TCP端口连接"""
        if not self.enable_tcp:
            return False, None  # 如果禁用TCP，直接返回失败
            
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tcp_timeout)
            result = sock.connect_ex((host, int(port)))
            latency = (time.time() - start_time) * 1000  # 毫秒
            sock.close()
            
            return result == 0, latency
        except:
            return False, None
    
    def test_download_speed(self, host):
        """测试下载速度（通过节点服务器下载测试文件）"""
        if not self.enable_speedtest:
            return False, 0, 0  # 如果禁用速度测试，直接返回
            
        try:
            # 选择测试文件
            test_url = self.speedtest_files[0]  # 使用第一个测试文件
            
            print(f"   📊📊 开始速度测试: {host}")
            start_time = time.time()
            
            # 设置超时
            response = requests.get(test_url, timeout=self.speedtest_timeout, stream=True)
            total_size = 0
            chunk_size = 10240  # 10KB
            
            # 读取数据流计算速度
            for chunk in response.iter_content(chunk_size=chunk_size):
                total_size += len(chunk)
                elapsed = time.time() - start_time
                
                # 如果超过超时时间，提前结束
                if elapsed > self.speedtest_timeout:
                    break
                    
                # 如果已经下载了足够的数据（5MB），提前结束
                if total_size > 5 * 1024 * 1024:
                    break
            
            end_time = time.time()
            download_time = end_time - start_time
            
            if download_time > 0 and total_size > 0:
                # 计算速度（Mbps）
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                # 计算速度（MB/s）
                speed_mbs = total_size / (download_time * 1024 * 1024)
                
                print(f"   📊📊 下载速度: {speed_mbps:.2f} Mbps ({speed_mbs:.2f} MB/s)")
                return True, speed_mbps, speed_mbs
            else:
                print(f"   📊📊 速度测试失败: 无数据")
                return False, 0, 0
                
        except requests.exceptions.Timeout:
            print(f"   📊📊 速度测试超时")
            return False, 0, 0
        except requests.exceptions.RequestException as e:
            print(f"   📊📊 速度测试错误: {e}")
            return False, 0, 0
        except Exception as e:
            print(f"   📊📊 速度测试异常: {e}")
            return False, 0, 0

    def test_url_latency(self, host):
        """测试URL访问延迟"""
        if not self.enable_url_test:
            return False, 0  # 如果禁用URL测试，直接返回
            
        try:
            best_latency = float('inf')
            success_count = 0
            
            # 测试多个URL，取最佳延迟
            for test_url in self.url_test_sites:
                try:
                    start_time = time.time()
                    response = requests.get(test_url, timeout=self.url_test_timeout, stream=False)
                    latency = (time.time() - start_time) * 1000  # 毫秒
                    
                    if response.status_code == 200:
                        success_count += 1
                        if latency < best_latency:
                            best_latency = latency
                            
                    # 只读取少量数据来测试连接
                    response.close()
                    
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.RequestException:
                    continue
                except Exception:
                    continue
            
            if success_count > 0 and best_latency != float('inf'):
                print(f"   🌐🌐 URL延迟: ✅ {best_latency:.1f}ms (成功{success_count}/{len(self.url_test_sites)}个站点)")
                return True, best_latency
            else:
                print(f"   🌐🌐 URL延迟: ❌❌❌❌❌❌❌❌ 失败")
                return False, 0
                
        except Exception as e:
            print(f"   🌐🌐 URL延迟测试异常: {e}")
            return False, 0
    
    def test_single_node(self, node, index):
        """测试单个节点的ICMP ping、TCP连接、下载速度和URL延迟"""
        config = node['config']
        original_config = node['original_config']
        
        # 提取服务器信息
        host, port = self.extract_server_info(config)
        
        if not host:
            return {
                'index': index,
                'original_config': original_config,
                'status': 'parse_error',
                'ping_success': False,
                'ping_latency': None,
                'tcp_success': False,
                'tcp_latency': None,
                'speed_success': False,
                'speed_mbps': 0,
                'speed_mbs': 0,
                'url_success': False,
                'url_latency': 0
            }
        
        print(f"\n🧪🧪🧪🧪🧪🧪🧪🧪 测试节点 {index}: {host}" + (f":{port}" if port else ""))
        
        # 1. 测试ICMP ping（根据开关决定）
        ping_success, ping_latency = False, None
        if self.enable_ping:
            ping_success, ping_latency = self.test_icmp_ping(host)
            if ping_success:
                print(f"   📡📡📡📡📡📡📡📡 ICMP Ping: ✅ {ping_latency:.1f}ms")
            else:
                print(f"   📡📡📡📡📡📡📡📡 ICMP Ping: ❌❌❌❌❌❌❌❌ 失败")
        else:
            print(f"   📡📡📡📡📡📡📡📡 ICMP Ping: 🔄🔄 已禁用")
        
        # 2. 测试TCP端口连接（根据开关决定）
        tcp_success, tcp_latency = False, None
        if self.enable_tcp and port:
            tcp_success, tcp_latency = self.test_tcp_connect(host, port)
            if tcp_success:
                print(f"   🔌🔌🔌🔌🔌🔌🔌🔌 TCP Port: ✅ {tcp_latency:.1f}ms")
            else:
                print(f"   🔌🔌🔌🔌🔌🔌🔌🔌 TCP Port: ❌❌❌❌❌❌❌❌ 失败")
        elif self.enable_tcp and not port:
            print(f"   🔌🔌🔌🔌🔌🔌🔌🔌 TCP Port: ⚠⚠⚠⚠⚠⚠⚠️ 无端口信息")
        else:
            print(f"   🔌🔌🔌🔌🔌🔌🔌🔌 TCP Port: 🔄🔄 已禁用")
        
        # 3. 测试下载速度（根据开关决定）
        speed_success, speed_mbps, speed_mbs = False, 0, 0
        if self.enable_speedtest:
            speed_success, speed_mbps, speed_mbs = self.test_download_speed(host)
        else:
            print(f"   📊📊📊📊📊📊📊📊 速度测试: 🔄🔄 已禁用")
        
        # 4. 测试URL延迟（根据开关决定）
        url_success, url_latency = False, 0
        if self.enable_url_test:
            url_success, url_latency = self.test_url_latency(host)
        else:
            print(f"   🌐🌐🌐🌐🌐🌐🌐🌐 URL延迟测试: 🔄🔄 已禁用")
        
        # 确定总体状态（考虑开关状态）
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
                
        if self.enable_url_test:
            total_tests += 1
            if url_success:
                success_count += 1
        
        # 根据成功率确定状态
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
            'url_success': url_success,
            'url_latency': url_latency,
            'ping_enabled': self.enable_ping,
            'tcp_enabled': self.enable_tcp,
            'speed_enabled': self.enable_speedtest,
            'url_enabled': self.enable_url_test,
            'success_count': success_count,
            'total_tests': total_tests
        }
    
    def run_comprehensive_test(self):
        """运行综合测试"""
        print("=" * 70)
        print("🔍🔍🔍🔍🔍🔍🔍🔍 节点连通性综合测试")
        print("=" * 70)
        print("📊📊📊📊📊📊📊📊 测试配置:")
        print(f"   📡📡📡📡📡📡📡📡 ICMP Ping: {'✅ 启用' if self.enable_ping else '❌❌ 禁用'}")
        print(f"   🔌🔌🔌🔌🔌🔌🔌🔌 TCP端口: {'✅ 启用' if self.enable_tcp else '❌❌ 禁用'}")
        print(f"   📊📊📊📊📊📊📊📊 速度测试: {'✅ 启用' if self.enable_speedtest else '❌❌ 禁用'}")
        print(f"   🌐🌐🌐🌐🌐🌐🌐🌐 URL延迟: {'✅ 启用' if self.enable_url_test else '❌❌ 禁用'}")
        print("=" * 70)
        
        nodes = self.read_nodes()
        if not nodes:
            return
        
        print(f"🚀🚀🚀🚀🚀🚀🚀🚀 开始测试 {len(nodes)} 个节点...")
        
        results = []
        
        # 逐个测试（避免并发过多）
        for i, node in enumerate(nodes, 1):  # 限制测试数量，速度测试较慢
            result = self.test_single_node(node, i)
            results.append(result)
            
            # 短暂延迟，避免请求过快
            time.sleep(1)
        
        # 生成详细报告并保存为txt
        self.generate_detailed_report(results)
        
        return results
    
    def generate_detailed_report(self, results):
        """生成详细报告并保存为txt格式"""
        print("\n" + "=" * 70)
        print("📊📊📊📊📊📊📊📊 详细测试报告")
        print("=" * 70)
        
        # 根据启用的测试类型调整过滤逻辑
        if not any([self.enable_ping, self.enable_tcp, self.enable_speedtest, self.enable_url_test]):
            print("⚠️⚠️⚠️⚠️ 警告: 所有测试均已禁用，无法进行有效测试")
            filtered_results = []
        else:
            # 过滤掉所有测试都失败的节点
            filtered_results = []
            for result in results:
                if result['status'] == 'parse_error':
                    continue
                    
                success_count = result['success_count']
                total_tests = result['total_tests']
                
                # 如果有任何测试成功，就保留
                if success_count > 0:
                    filtered_results.append(result)
        
        # 统计信息
        total = len(results)
        total_filtered = len(filtered_results)
        parse_errors = len([r for r in results if r['status'] == 'parse_error'])
        all_failed = total - total_filtered - parse_errors
        
        print("📈📈📈📈📈📈📈📈 总体统计:")
        print(f"   总测试节点: {total}")
        print(f"   🔧🔧🔧🔧 解析错误: {parse_errors}")
        print(f"   ❌❌❌❌❌❌❌❌ 完全失败: {all_failed}")
        print(f"   ✅ 有效节点: {total_filtered}")
        
        # 显示测试类型统计
        if self.enable_ping:
            ping_success = len([r for r in filtered_results if r['ping_success']])
            print(f"   📡📡 Ping成功: {ping_success}/{total_filtered}")
            
        if self.enable_tcp:
            tcp_success = len([r for r in filtered_results if r['tcp_success']])
            print(f"   🔌🔌 TCP成功: {tcp_success}/{total_filtered}")
            
        if self.enable_speedtest:
            speed_success = len([r for r in filtered_results if r['speed_success']])
            print(f"   📊📊 速度测试成功: {speed_success}/{total_filtered}")
            
        if self.enable_url_test:
            url_success = len([r for r in filtered_results if r['url_success']])
            print(f"   🌐🌐 URL延迟成功: {url_success}/{total_filtered}")
        
        # 按速度排序（如果启用了速度测试）
        if self.enable_speedtest:
            # 优先按速度排序
            def get_speed_sort_key(result):
                if result['speed_success'] and result['speed_mbps'] > 0:
                    return -result['speed_mbps']  # 负值用于降序排序
                elif result['url_success'] and result['url_latency'] > 0:
                    return result['url_latency'] + 5000
                elif result['tcp_success'] and result['tcp_latency']:
                    return result['tcp_latency'] + 10000
                elif result['ping_success'] and result['ping_latency']:
                    return result['ping_latency'] + 20000
                else:
                    return float('inf')
            
            filtered_results.sort(key=get_speed_sort_key)
            
            print(f"\n🏆🏆🏆🏆🏆🏆🏆🏆 最佳节点 (按下载速度排序):")
            for i, node in enumerate(filtered_results[:10], 1):
                ping_info = f"{node['ping_latency']:.1f}ms" if node['ping_success'] and self.enable_ping else "禁用" if not self.enable_ping else "失败"
                tcp_info = f"{node['tcp_latency']:.1f}ms" if node['tcp_success'] and self.enable_tcp else "禁用" if not self.enable_tcp else "失败"
                speed_info = f"{node['speed_mbps']:.2f}Mbps" if node['speed_success'] and self.enable_speedtest else "禁用" if not self.enable_speedtest else "失败"
                url_info = f"{node['url_latency']:.1f}ms" if node['url_success'] and self.enable_url_test else "禁用" if not self.enable_url_test else "失败"
                
                status_icon = "✅" if node['success_count'] == node['total_tests'] else "⚠️"
                
                print(f"{i:2d}. {status_icon} {node['host']:15} "
                      f"Ping:{ping_info:>8} TCP:{tcp_info:>8} Speed:{speed_info:>10} URL:{url_info:>8}")
        
        else:
            # 按延迟排序（如果没有速度测试）
            def get_latency_sort_key(result):
                if result['url_success'] and result['url_latency'] > 0:
                    return result['url_latency']
                elif result['tcp_success'] and result['tcp_latency']:
                    return result['tcp_latency'] + 1000
                elif result['ping_success'] and result['ping_latency']:
                    return result['ping_latency'] + 2000
                else:
                    return float('inf')
            
            filtered_results.sort(key=get_latency_sort_key)
            
            print(f"\n🏆🏆🏆🏆🏆🏆🏆🏆 最佳节点 (按延迟排序):")
            for i, node in enumerate(filtered_results[:10], 1):
                ping_info = f"{node['ping_latency']:.1f}ms" if node['ping_success'] and self.enable_ping else "禁用" if not self.enable_ping else "失败"
                tcp_info = f"{node['tcp_latency']:.1f}ms" if node['tcp_success'] and self.enable_tcp else "禁用" if not self.enable_tcp else "失败"
                speed_info = f"{node['speed_mbps']:.2f}Mbps" if node['speed_success'] and self.enable_speedtest else "禁用" if not self.enable_speedtest else "失败"
                url_info = f"{node['url_latency']:.1f}ms" if node['url_success'] and self.enable_url_test else "禁用" if not self.enable_url_test else "失败"
                
                status_icon = "✅" if node['success_count'] == node['total_tests'] else "⚠️"
                
                print(f"{i:2d}. {status_icon} {node['host']:15} "
                      f"Ping:{ping_info:>8} TCP:{tcp_info:>8} Speed:{speed_info:>10} URL:{url_info:>8}")
        
        # 保存为TXT文件（每行一个原始链接）
        if filtered_results:
            with open('ping.txt', 'w', encoding='utf-8') as f:
                for result in filtered_results:
                    # 直接写入原始链接，一行一个
                    f.write(result['original_config'] + '\n')
        
        # 同时保存JSON格式的详细结果
        json_data = {
            'test_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'test_config': {
                'enable_ping': self.enable_ping,
                'enable_tcp': self.enable_tcp,
                'enable_speedtest': self.enable_speedtest,
                'enable_url_test': self.enable_url_test
            },
            'total_nodes_tested': total,
            'filtered_nodes_count': total_filtered,
            'statistics': {
                'parse_errors': parse_errors,
                'all_failed': all_failed,
                'ping_success': len([r for r in filtered_results if r['ping_success']]) if self.enable_ping else 0,
                'tcp_success': len([r for r in filtered_results if r['tcp_success']]) if self.enable_tcp else 0,
                'speed_success': len([r for r in filtered_results if r['speed_success']]) if self.enable_speedtest else 0,
                'url_success': len([r for r in filtered_results if r['url_success']]) if self.enable_url_test else 0
            },
            'nodes_sorted': [
                {
                    'original_config': r['original_config'],
                    'host': r.get('host'),
                    'port': r.get('port'),
                    'status': r['status'],
                    'ping_latency': r.get('ping_latency'),
                    'tcp_latency': r.get('tcp_latency'),
                    'speed_mbps': r.get('speed_mbps'),
                    'speed_mbs': r.get('speed_mbs'),
                    'url_latency': r.get('url_latency'),
                    'success_count': r.get('success_count'),
                    'total_tests': r.get('total_tests')
                }
                for r in filtered_results
            ]
        }
        
        with open('connectivity_results.json', 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾💾💾💾💾💾💾 保存结果:")
        if filtered_results:
            print(f"   📄📄 filtered_nodes.txt - {total_filtered} 个有效节点")
        else:
            print(f"   📄📄 filtered_nodes.txt - 无有效节点")
        print(f"   📊📊 connectivity_results.json - 详细测试结果")
        print(f"   🔗🔗 过滤掉了 {all_failed} 个完全失败的节点")

def main():
    """主函数"""
    # 检查文件是否存在
    if not os.path.exists("sub.txt"):
        print("❌❌❌❌ 请确保 sub.txt 文件存在于当前目录")
        print("📁📁📁📁 当前目录文件:")
        for file in os.listdir('.'):
            print(f"   - {file}")
        return
    
    # 在这里设置测试开关
    enable_ping = False      # Ping测试开关
    enable_tcp = True        # TCP测试开关  
    enable_speedtest = flase
    enable_url_test=True   # 速度测试开关
    
    tester = NodeConnectivityTester(
        enable_ping=enable_ping, 
        enable_tcp=enable_tcp, 
        enable_speedtest=enable_speedtest,
        enable_url_test=enable_url_test)
    results = tester.run_comprehensive_test()

if __name__ == "__main__":
    main()
    
