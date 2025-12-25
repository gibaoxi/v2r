#!/usr/bin/env python3
import os
import time
import socket
import subprocess
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class NodeConnectivityTester:
    def __init__(self):
        self.sub_file = "sub.txt"
        self.ping_timeout = 3
        self.tcp_timeout = 5
        self.max_workers = 3
        
    def read_nodes(self):
        """读取节点配置"""
        if not os.path.exists(self.sub_file):
            print(f"❌ 错误: 找不到 {self.sub_file}")
            return []
            
        nodes = []
        with open(self.sub_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    nodes.append({
                        'line_num': line_num,
                        'config': clean_line
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
    
    def test_single_node(self, node, index):
        """测试单个节点的ICMP ping和TCP连接"""
        config = node['config']
        
        # 提取服务器信息
        host, port = self.extract_server_info(config)
        
        if not host:
            return {
                'index': index,
                'config': config[:60] + '...',
                'status': 'parse_error',
                'ping_success': False,
                'ping_latency': None,
                'tcp_success': False,
                'tcp_latency': None
            }
        
        print(f"\n🧪 测试节点 {index}: {host}" + (f":{port}" if port else ""))
        
        # 1. 测试ICMP ping
        ping_success, ping_latency = self.test_icmp_ping(host)
        
        if ping_success:
            print(f"   📡 ICMP Ping: ✅ {ping_latency:.1f}ms")
        else:
            print(f"   📡 ICMP Ping: ❌ 失败")
        
        # 2. 测试TCP端口连接（如果有端口）
        tcp_success, tcp_latency = False, None
        if port:
            tcp_success, tcp_latency = self.test_tcp_connect(host, port)
            if tcp_success:
                print(f"   🔌 TCP Port: ✅ {tcp_latency:.1f}ms")
            else:
                print(f"   🔌 TCP Port: ❌ 失败")
        else:
            print(f"   🔌 TCP Port: ⚠️ 无端口信息")
        
        # 确定总体状态
        if ping_success and tcp_success:
            status = 'both_success'
        elif ping_success:
            status = 'ping_only'
        elif tcp_success:
            status = 'tcp_only'
        else:
            status = 'both_failed'
        
        return {
            'index': index,
            'host': host,
            'port': port,
            'config_preview': config[:60] + '...',
            'status': status,
            'ping_success': ping_success,
            'ping_latency': ping_latency,
            'tcp_success': tcp_success,
            'tcp_latency': tcp_latency
        }
    
    def run_comprehensive_test(self):
        """运行综合测试"""
        print("=" * 70)
        print("🔍 节点连通性综合测试")
        print("=" * 70)
        print("📊 测试内容:")
        print("   1. 📡 ICMP Ping - 测试服务器网络连通性")
        print("   2. 🔌 TCP端口 - 测试代理服务可用性")
        print("=" * 70)
        
        nodes = self.read_nodes()
        if not nodes:
            return
        
        print(f"🚀 开始测试 {len(nodes)} 个节点...")
        
        results = []
        
        # 逐个测试（避免并发过多）
        for i, node in enumerate(nodes[:15], 1):  # 限制测试数量
            result = self.test_single_node(node, i)
            results.append(result)
            
            # 短暂延迟，避免请求过快
            time.sleep(0.5)
        
        # 生成详细报告
        self.generate_detailed_report(results)
        
        return results
    
    def generate_detailed_report(self, results):
        """生成详细测试报告"""
        print("\n" + "=" * 70)
        print("📊 详细测试报告")
        print("=" * 70)
        
        # 统计信息
        total = len(results)
        both_success = len([r for r in results if r['status'] == 'both_success'])
        ping_only = len([r for r in results if r['status'] == 'ping_only'])
        tcp_only = len([r for r in results if r['status'] == 'tcp_only'])
        both_failed = len([r for r in results if r['status'] == 'both_failed'])
        parse_errors = len([r for r in results if r['status'] == 'parse_error'])
        
        print("📈 总体统计:")
        print(f"   总测试节点: {total}")
        print(f"   ✅ ICMP+Ping均成功: {both_success}")
        print(f"   📡 仅ICMP Ping成功: {ping_only}")
        print(f"   🔌 仅TCP端口成功: {tcp_only}")
        print(f"   ❌ 两者均失败: {both_failed}")
        print(f"   🔧 解析错误: {parse_errors}")
        
        # 显示最佳节点（按TCP延迟排序）
        successful_nodes = [r for r in results if r['tcp_success']]
        if successful_nodes:
            successful_nodes.sort(key=lambda x: x['tcp_latency'] or float('inf'))
            
            print(f"\n🏆 TCP延迟最佳节点:")
            for i, node in enumerate(successful_nodes[:10], 1):
                ping_info = f"{node['ping_latency']:.1f}ms" if node['ping_success'] else "失败"
                tcp_info = f"{node['tcp_latency']:.1f}ms"
                print(f"{i:2d}. {node['host']:15} Ping:{ping_info:>8} TCP:{tcp_info:>8}")
        
        # 显示ICMP延迟最佳节点
        ping_nodes = [r for r in results if r['ping_success']]
        if ping_nodes:
            ping_nodes.sort(key=lambda x: x['ping_latency'])
            
            print(f"\n📡 ICMP延迟最佳节点:")
            for i, node in enumerate(ping_nodes[:5], 1):
                tcp_info = f"{node['tcp_latency']:.1f}ms" if node['tcp_success'] else "失败"
                print(f"{i:2d}. {node['host']:15} Ping:{node['ping_latency']:6.1f}ms TCP:{tcp_info:>8}")
        
        # 保存详细结果
        report_data = {
            'test_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_nodes': total,
            'statistics': {
                'both_success': both_success,
                'ping_only': ping_only,
                'tcp_only': tcp_only,
                'both_failed': both_failed,
                'parse_errors': parse_errors
            },
            'results': [
                {
                    'host': r.get('host'),
                    'port': r.get('port'),
                    'status': r['status'],
                    'ping_latency': r.get('ping_latency'),
                    'tcp_latency': r.get('tcp_latency'),
                    'config_preview': r.get('config_preview')
                }
                for r in results
            ]
        }
        
        with open('connectivity_results.json', 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾 详细结果已保存到: connectivity_results.json")

def main():
    """主函数"""
    # 检查文件是否存在
    if not os.path.exists("sub.txt"):
        print("❌ 请确保 sub.txt 文件存在于当前目录")
        print("📁 当前目录文件:")
        for file in os.listdir('.'):
            print(f"   - {file}")
        return
    
    tester = NodeConnectivityTester()
    results = tester.run_comprehensive_test()

if __name__ == "__main__":
    main()
