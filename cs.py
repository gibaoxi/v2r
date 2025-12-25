#!/usr/bin/env python3
import os
import json
import re
import base64
import time
import socket
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

class GitHubNodeTester:
    def __init__(self):
        self.sub_file = "sub.txt"  # 同文件夹下的文件
        self.timeout = 8
        self.max_workers = 3  # GitHub Actions限制并发数
        self.results = []
    
    def check_sub_file(self):
        """检查sub.txt文件是否存在"""
        if not os.path.exists(self.sub_file):
            print(f"❌ 错误: 当前目录下找不到 {self.sub_file}")
            print(f"📁 当前目录文件列表:")
            for file in os.listdir('.'):
                print(f"   - {file}")
            return False
        return True
    
    def read_subscription(self):
        """读取订阅文件内容"""
        try:
            with open(self.sub_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print(f"✅ 成功读取 {self.sub_file}")
            print(f"📊 文件大小: {len(content)} 字符")
            return content
        except Exception as e:
            print(f"❌ 读取文件失败: {e}")
            return None
    
    def extract_nodes(self, content):
        """提取所有节点链接"""
        patterns = [
            r'vmess://[A-Za-z0-9+/=]+',
            r'vless://[^\s]+',
            r'trojan://[^\s]+', 
            r'ss://[^\s]+',
            r'hysteria2://[^\s]+'
        ]
        
        nodes = []
        for pattern in patterns:
            matches = re.findall(pattern, content)
            nodes.extend(matches)
        
        print(f"🔍 发现 {len(nodes)} 个节点")
        return nodes
    
    def safe_parse_vmess(self, vmess_url):
        """安全解析VMess"""
        try:
            encoded = vmess_url[8:]  # 去掉'vmess://'
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            config = json.loads(decoded)
            
            return {
                'type': 'vmess',
                'address': config.get('add', ''),
                'port': config.get('port', ''),
                'remark': config.get('ps', '')[:20]
            }
        except:
            return {'error': '解析失败'}
    
    def safe_parse_vless_trojan(self, url):
        """解析VLESS/Trojan"""
        try:
            parsed = urlparse(url)
            return {
                'type': 'vless' if url.startswith('vless') else 'trojan',
                'address': parsed.hostname,
                'port': parsed.port,
                'protocol': parsed.scheme
            }
        except:
            return {'error': '解析失败'}
    
    def safe_parse_ss(self, ss_url):
        """解析Shadowsocks"""
        try:
            if '@' in ss_url:
                parts = ss_url[5:].split('@')  # 去掉'ss://'
                host_port = parts[1].split('#')[0]
                host, port = host_port.split(':')
                return {
                    'type': 'ss',
                    'address': host,
                    'port': port
                }
            return {'error': '解析失败'}
        except:
            return {'error': '解析失败'}
    
    def parse_node(self, node_url):
        """统一解析节点"""
        if node_url.startswith('vmess://'):
            return self.safe_parse_vmess(node_url)
        elif node_url.startswith('vless://'):
            return self.safe_parse_vless_trojan(node_url)
        elif node_url.startswith('trojan://'):
            return self.safe_parse_vless_trojan(node_url)
        elif node_url.startswith('ss://'):
            return self.safe_parse_ss(node_url)
        elif node_url.startswith('hysteria2://'):
            return {'type': 'hysteria2', 'address': '特殊协议'}
        else:
            return {'error': '未知协议'}
    
    def github_safe_connect_test(self, host, port):
        """GitHub环境安全的连接测试"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, int(port)))
            connect_time = (time.time() - start_time) * 1000
            sock.close()
            
            return result == 0, connect_time
        except:
            return False, None
    
    def test_single_node(self, node_url, index):
        """测试单个节点"""
        # 解析节点信息
        node_info = self.parse_node(node_url)
        
        if 'error' in node_info:
            return {
                'index': index,
                'url': node_url[:60] + '...',
                'info': node_info,
                'status': 'parse_error',
                'latency': None
            }
        
        # 测试连接
        success, latency = self.github_safe_connect_test(
            node_info['address'], 
            node_info.get('port', 80)
        )
        
        status = 'success' if success else 'connect_failed'
        
        return {
            'index': index,
            'url': node_url[:60] + '...',
            'info': node_info,
            'status': status,
            'latency': latency
        }
    
    def run_test(self):
        """执行完整测试流程"""
        print("=" * 60)
        print("🚀 GitHub节点连通性测试")
        print("=" * 60)
        
        # 1. 检查文件
        if not self.check_sub_file():
            return None
        
        # 2. 读取内容
        content = self.read_subscription()
        if not content:
            return None
        
        # 3. 提取节点
        nodes = self.extract_nodes(content)
        if not nodes:
            print("❌ 未找到有效节点")
            return None
        
        # 限制测试数量避免超时
        test_nodes = nodes[:20]
        print(f"🧪 测试前 {len(test_nodes)} 个节点")
        
        results = []
        
        # 并发测试
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for i, node_url in enumerate(test_nodes, 1):
                future = executor.submit(self.test_single_node, node_url, i)
                futures.append(future)
            
            for i, future in enumerate(as_completed(futures), 1):
                try:
                    result = future.result()
                    results.append(result)
                    
                    # 实时显示进度
                    icon = '✅' if result['status'] == 'success' else '❌'
                    latency_info = f"{result['latency']:.1f}ms" if result['latency'] else "超时"
                    
                    print(f"{icon} [{result['index']:2d}] {result['info']['type']:10} {result['info']['address']:15} 延迟: {latency_info}")
                    
                except Exception as e:
                    print(f"💥 测试异常: {e}")
        
        return self.generate_report(results)
    
    def generate_report(self, results):
        """生成测试报告"""
        print("\n" + "=" * 60)
        print("📊 测试报告")
        print("=" * 60)
        
        # 统计信息
        total = len(results)
        success_nodes = [r for r in results if r['status'] == 'success']
        success_count = len(success_nodes)
        
        print(f"📈 统计信息:")
        print(f"   总节点数: {total}")
        print(f"   ✅ 连通正常: {success_count}")
        print(f"   ❌ 连接失败: {total - success_count}")
        print(f"   📊 成功率: {success_count/total*100:.1f}%")
        
        # 显示最佳节点
        if success_nodes:
            success_nodes.sort(key=lambda x: x['latency'] or float('inf'))
            
            print(f"\n🏆 最佳节点 (按延迟排序):")
            for i, node in enumerate(success_nodes[:10], 1):
                info = node['info']
                print(f"{i:2d}. {info['type']:10} {info['address']:15}:{info.get('port', '?'):5} 延迟: {node['latency']:6.1f}ms")
        
        # 保存详细结果
        report_data = {
            'test_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_nodes': total,
            'successful_nodes': success_count,
            'success_rate': round(success_count/total*100, 1),
            'top_nodes': [
                {
                    'type': node['info']['type'],
                    'address': node['info']['address'],
                    'port': node['info'].get('port'),
                    'latency': node['latency'],
                    'remark': node['info'].get('remark', '')
                }
                for node in success_nodes[:5]
            ]
        }
        
        # 保存到文件
        with open('test_results.json', 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾 详细结果已保存到: test_results.json")
        
        return report_data

def main():
    """主函数"""
    tester = GitHubNodeTester()
    results = tester.run_test()
    
    # 设置GitHub Actions输出
    if results and os.getenv('GITHUB_ACTIONS'):
        success_rate = results['success_rate']
        best_latency = results['top_nodes'][0]['latency'] if results['top_nodes'] else 0
        
        print(f"::set-output name=success_rate::{success_rate}")
        print(f"::set-output name=best_latency::{best_latency}")
        print(f"::set-output name=total_nodes::{results['total_nodes']}")

if __name__ == "__main__":
    main()
