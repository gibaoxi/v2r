#!/usr/bin/env python3
"""
高速代理连通性测试工具
专注于快速、准确的代理节点测试
"""

import asyncio
import aiohttp
import time
import json
import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
import base64
import re

@dataclass
class ProxyConfig:
    """代理配置"""
    url: str
    protocol: str
    host: str
    port: int
    name: str = ""
    latency: float = 0.0
    tcp_latency: float = 0.0  # TCP连接延迟
    status: str = "pending"
    error: str = ""
    tcp_connected: bool = False  # TCP连接状态

class FastProxyTester:
    def __init__(self, max_concurrent=50, timeout=8, tcp_timeout=8):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.tcp_timeout = tcp_timeout  # TCP连接超时时间
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # 测试目标（选择响应快的网站）
        self.test_targets = [
            "https://httpbin.org/ip",
            "https://api.ipify.org?format=json"
        ]
    
    def parse_proxy_links(self, file_path: str) -> List[ProxyConfig]:
        """从文件解析代理链接"""
        configs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    config = self._parse_single_link(line)
                    if config:
                        configs.append(config)
            
            print(f"✅ 解析完成: {len(configs)} 个代理配置")
            return configs
            
        except Exception as e:
            print(f"❌❌❌❌ 解析文件失败: {e}")
            return []
    
    def _parse_single_link(self, link: str) -> Optional[ProxyConfig]:
        """解析单个代理链接"""
        try:
            if link.startswith('ss://'):
                return self._parse_ss(link)
            elif link.startswith('vmess://'):
                return self._parse_vmess(link)
            elif link.startswith('trojan://'):
                return self._parse_trojan(link)
            elif link.startswith('vless://'):
                return self._parse_vless(link)
            else:
                return None
        except:
            return None
    
    def _parse_ss(self, link: str) -> Optional[ProxyConfig]:
        """解析SS链接"""
        try:
            # ss://method:password@host:port#name
            if '#' in link:
                link, name = link.split('#', 1)
                name = name.strip()
            else:
                name = "SS-Node"
            
            # 提取基础部分
            if '@' in link:
                user_info, server_part = link[5:].split('@', 1)
            else:
                # 处理base64编码的格式
                b64_part = link[5:].split('#')[0]
                decoded = base64.b64decode(b64_part + '==').decode()
                user_info, server_part = decoded.split('@', 1)
            
            host, port = server_part.split(':', 1)
            port = int(port)
            
            return ProxyConfig(
                url=link,
                protocol="ss",
                host=host,
                port=port,
                name=name
            )
        except:
            return None
    
    def _parse_vmess(self, link: str) -> Optional[ProxyConfig]:
        """解析VMess链接"""
        try:
            b64_data = link[8:].split('#')[0]
            decoded = base64.b64decode(b64_data + '==').decode()
            config = json.loads(decoded)
            
            name = config.get('ps', 'VMess-Node')
            host = config.get('add', '')
            port = int(config.get('port', 443))
            
            return ProxyConfig(
                url=link,
                protocol="vmess",
                host=host,
                port=port,
                name=name
            )
        except:
            return None
    
    def _parse_trojan(self, link: str) -> Optional[ProxyConfig]:
        """解析Trojan链接"""
        try:
            parsed = urlparse(link)
            host = parsed.hostname
            port = parsed.port or 443
            name = parsed.fragment or "Trojan-Node"
            
            return ProxyConfig(
                url=link,
                protocol="trojan",
                host=host,
                port=port,
                name=name
            )
        except:
            return None
    
    def _parse_vless(self, link: str) -> Optional[ProxyConfig]:
        """解析VLESS链接"""
        try:
            parsed = urlparse(link)
            host = parsed.hostname
            port = parsed.port or 443
            name = parsed.fragment or "VLESS-Node"
            
            return ProxyConfig(
                url=link,
                protocol="vless",
                host=host,
                port=port,
                name=name
            )
        except:
            return None
    
    async def test_tcp_connectivity(self, config: ProxyConfig) -> bool:
        """测试TCP连通性"""
        try:
            # 异步TCP连接测试
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(config.host, config.port),
                timeout=self.tcp_timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            return False
        except Exception as e:
            return False
    
    async def test_single_proxy(self, config: ProxyConfig) -> ProxyConfig:
        """测试单个代理"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                # 第一步：进行TCP连接测试（无论成功与否都继续）
                tcp_start = time.time()
                tcp_connected = await self.test_tcp_connectivity(config)
                tcp_latency = (time.time() - tcp_start) * 1000
                
                # 设置TCP连接状态
                config.tcp_connected = tcp_connected
                config.tcp_latency = round(tcp_latency, 2)  # 记录TCP连接延迟
                
                # 第二步：无论TCP测试结果如何，都进行HTTP访问测试
                async with aiohttp.ClientSession() as session:
                    # 随机选择一个测试目标
                    test_url = random.choice(self.test_targets)
                    
                    proxy_url = self._build_proxy_url(config)
                    
                    try:
                        async with session.get(
                            test_url,
                            proxy=proxy_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            headers={'User-Agent': 'Mozilla/5.0'}
                        ) as response:
                            if response.status in [200, 204]:
                                total_latency = (time.time() - start_time) * 1000
                                config.latency = round(total_latency, 2)
                                config.status = "success"
                            else:
                                config.status = "http_failed"
                                config.error = f"HTTP {response.status}"
                                
                    except Exception as http_error:
                        # HTTP测试失败
                        if not tcp_connected:
                            config.status = "tcp_http_failed"
                            config.error = f"TCP失败, HTTP错误: {str(http_error)}"
                        else:
                            config.status = "http_failed"
                            config.error = f"HTTP错误: {str(http_error)}"
                
            except asyncio.TimeoutError:
                config.status = "timeout"
                config.error = "请求超时"
            except Exception as e:
                config.status = "error"
                config.error = str(e)
            
            return config
    
    def _build_proxy_url(self, config: ProxyConfig) -> str:
        """构建代理URL"""
        if config.protocol == "ss":
            return f"socks5://{config.host}:{config.port}"
        elif config.protocol in ["vmess", "vless", "trojan"]:
            return f"socks5://{config.host}:{config.port}"
        else:
            return f"http://{config.host}:{config.port}"
    
    async def batch_test(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        """批量测试代理"""
        print(f"🚀🚀🚀🚀 开始测试 {len(configs)} 个代理节点...")
        print(f"⚡⚡⚡⚡ 并发数: {self.max_concurrent}, TCP超时: {self.tcp_timeout}秒, HTTP超时: {self.timeout}秒")
        
        tasks = [self.test_single_proxy(config) for config in configs]
        
        # 显示进度
        completed = 0
        total = len(tasks)
        
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result = await task
            completed += 1
            
            # 每完成10个或最后显示进度
            if completed % 10 == 0 or completed == total:
                success_count = len([c for c in configs if c.status == "success"])
                tcp_success_count = len([c for c in configs if c.tcp_connected])
                print(f"📊📊📊📊 进度: {completed}/{total} | TCP成功: {tcp_success_count} | HTTP成功: {success_count}")
        
        return configs
    
    def save_results(self, configs: List[ProxyConfig], output_file: str):
        """保存测试结果"""
        # 分类节点
        working_configs = [c for c in configs if c.status == "success"]
        working_configs.sort(key=lambda x: x.latency)
        
        tcp_success_http_failed = [c for c in configs if c.tcp_connected and c.status != "success"]
        tcp_failed_http_success = [c for c in configs if not c.tcp_connected and c.status == "success"]
        both_failed = [c for c in configs if not c.tcp_connected and c.status != "success"]
        
        # 保存可用节点（按HTTP延迟排序）
        with open(f"working_{output_file}", 'w', encoding='utf-8') as f:
            for config in working_configs:
                tcp_status = "TCP成功" if config.tcp_connected else "TCP失败"
                f.write(f"{config.url} # {config.latency}ms ({tcp_status})\n")
        
        # 保存特殊情况：TCP失败但HTTP成功的节点
        with open(f"special_{output_file}", 'w', encoding='utf-8') as f:
            for config in tcp_failed_http_success:
                f.write(f"{config.url} # TCP失败但HTTP成功: {config.latency}ms\n")
        
        # 保存TCP成功但HTTP失败的节点
        with open(f"tcp_only_{output_file}", 'w', encoding='utf-8') as f:
            for config in tcp_success_http_failed:
                f.write(f"{config.url} # TCP成功但HTTP失败: {config.error}\n")
        
        # 保存全部结果（含统计）
        with open(f"full_{output_file}", 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("代理连通性详细测试报告\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"测试时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总节点数: {len(configs)}\n")
            f.write(f"TCP连接成功: {len([c for c in configs if c.tcp_connected])}\n")
            f.write(f"HTTP测试成功: {len(working_configs)}\n")
            f.write(f"TCP成功但HTTP失败: {len(tcp_success_http_failed)}\n")
            f.write(f"TCP失败但HTTP成功: {len(tcp_failed_http_success)}\n")
            f.write(f"TCP和HTTP都失败: {len(both_failed)}\n")
            f.write(f"最终成功率: {len(working_configs)/len(configs)*100:.1f}%\n\n")
            
            # 显示所有可用节点（包括特殊情况）
            all_working = working_configs + tcp_failed_http_success
            all_working.sort(key=lambda x: x.latency)
            
            if all_working:
                f.write("🏆 所有可用节点（按HTTP延迟排序）:\n")
                for i, config in enumerate(all_working, 1):
                    tcp_status = "TCP成功" if config.tcp_connected else "TCP失败"
                    f.write(f"{i:2d}. {config.latency:6.1f}ms ({tcp_status}) - {config.name}\n")
                    f.write(f"    {config.url}\n\n")
            
            # 显示TCP成功但HTTP失败的节点
            if tcp_success_http_failed:
                f.write("\n" + "=" * 60 + "\n")
                f.write("TCP成功但HTTP失败的节点:\n")
                f.write("=" * 60 + "\n")
                for config in tcp_success_http_failed:
                    f.write(f"{config.url} # 错误: {config.error}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("所有可用节点:\n")
            f.write("=" * 60 + "\n")
            for config in working_configs:
                f.write(f"{config.url} # {config.latency}ms\n")
        
        print(f"✅ 结果已保存:")
        print(f"   📁 可用节点: working_{output_file}")
        print(f"   📁 特殊情况: special_{output_file}")
        print(f"   📁 TCP-only: tcp_only_{output_file}")
        print(f"   📊 完整报告: full_{output_file}")
    
    def print_statistics(self, configs: List[ProxyConfig]):
        """打印统计信息"""
        working = [c for c in configs if c.status == "success"]
        tcp_success = [c for c in configs if c.tcp_connected]
        tcp_failed = [c for c in configs if not c.tcp_connected]
        tcp_success_http_failed = [c for c in configs if c.tcp_connected and c.status != "success"]
        tcp_failed_http_success = [c for c in configs if not c.tcp_connected and c.status == "success"]
        
        print("\n" + "=" * 60)
        print("📈📈📈📈 详细测试统计报告")
        print("=" * 60)
        print(f"总节点数: {len(configs)}")
        print(f"TCP连接成功: {len(tcp_success)} ({len(tcp_success)/len(configs)*100:.1f}%)")
        print(f"HTTP测试成功: {len(working)} ({len(working)/len(configs)*100:.1f}%)")
        print(f"TCP成功但HTTP失败: {len(tcp_success_http_failed)}")
        print(f"TCP失败但HTTP成功: {len(tcp_failed_http_success)}")
        print(f"TCP和HTTP都失败: {len(tcp_failed) - len(tcp_failed_http_success)}")
        
        # TCP延迟统计
        if tcp_success:
            tcp_latencies = [c.tcp_latency for c in tcp_success if hasattr(c, 'tcp_latency')]
            avg_tcp_latency = sum(tcp_latencies) / len(tcp_latencies)
            min_tcp_latency = min(tcp_latencies)
            max_tcp_latency = max(tcp_latencies)
            
            print(f"\n⏱ TCP连接延迟统计:")
            print(f"  平均: {avg_tcp_latency:.1f}ms")
            print(f"  最低: {min_tcp_latency:.1f}ms")
            print(f"  最高: {max_tcp_latency:.1f}ms")
        
        if working:
            # HTTP延迟统计
            http_latencies = [c.latency for c in working]
            avg_http_latency = sum(http_latencies) / len(http_latencies)
            min_http_latency = min(http_latencies)
            max_http_latency = max(http_latencies)
            
            print(f"\n⏱ HTTP请求延迟统计:")
            print(f"  平均: {avg_http_latency:.1f}ms")
            print(f"  最低: {min_http_latency:.1f}ms")
            print(f"  最高: {max_http_latency:.1f}ms")
            
            # 按协议统计
            protocol_stats = {}
            for config in working:
                protocol_stats[config.protocol] = protocol_stats.get(config.protocol, 0) + 1
            
            print(f"\n📡📡📡📡 协议分布:")
            for protocol, count in protocol_stats.items():
                percentage = count / len(working) * 100
                print(f"  {protocol.upper():>10}: {count:>3} ({percentage:.1f}%)")
            
            # 显示最快节点
            fastest = sorted(working, key=lambda x: x.latency)[:5]
            print(f"\n🏆🏆🏆🏆 最快的前5个节点:")
            for i, config in enumerate(fastest, 1):
                print(f"  {i}. {config.latency:5.1f}ms - {config.name}")
        
        # 显示特殊情况统计
        if tcp_failed_http_success:
            print(f"\n🔍 特殊情况: TCP失败但HTTP成功的节点 ({len(tcp_failed_http_success)} 个)")
            print("  这可能是因为TCP测试时网络波动，但实际代理可用")
        
        if tcp_success_http_failed:
            print(f"\n⚠️ TCP成功但HTTP失败的节点 ({len(tcp_success_http_failed)} 个):")
            error_stats = {}
            for config in tcp_success_http_failed:
                error_stats[config.error] = error_stats.get(config.error, 0) + 1
            
            for error, count in error_stats.items():
                print(f"  {error}: {count} 个")

async def main():
    """主函数"""
    print("🚀🚀🚀🚀 高速代理连通性测试工具 (增强版 - 完整测试)")
    print("=" * 50)
    
    # 配置参数
    input_file = "working_proxy_test_results1.txt"  # 你的代理列表文件
    output_file = "proxy_test_results.txt"
    max_concurrent = 30    # 并发数（可根据网络调整）
    timeout = 6            # HTTP超时时间（秒）
    tcp_timeout = 3        # TCP连接超时时间（秒）
    
    # 创建测试器
    tester = FastProxyTester(
        max_concurrent=max_concurrent, 
        timeout=timeout, 
        tcp_timeout=tcp_timeout
    )
    
    # 解析代理配置
    configs = tester.parse_proxy_links(input_file)
    if not configs:
        print("❌❌❌❌ 没有找到可用的代理配置")
        return
    
    # 开始测试
    start_time = time.time()
    results = await tester.batch_test(configs)
    end_time = time.time()
    
    # 显示结果
    tester.print_statistics(results)
    
    # 保存结果
    tester.save_results(results, output_file)
    
    # 显示总耗时
    total_time = end_time - start_time
    print(f"\n⏰⏰⏰⏰⏰⏰⏰⏰⏰ 总耗时: {total_time:.1f}秒")
    print(f"📊📊📊📊 测试速度: {len(configs)/total_time:.1f} 节点/秒")

if __name__ == "__main__":
    # 运行测试
    asyncio.run(main())
