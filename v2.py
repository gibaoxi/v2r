#!/usr/bin/env python3
import os
import sys
import time
import json
import requests
import subprocess
import psutil
import base64
from urllib.parse import urlparse
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class GitHubV2RayTester:
    def __init__(self):
        self.v2ray_path = "./v2ray/v2ray"
        self.config_path = "./v2ray/config.json"
        self.local_port = 10808
        self.api_port = 10085
        self.v2ray_process = None
        
        # 测试网站
        self.test_urls = [
            "https://www.google.com",
            "https://www.github.com",
            "https://www.cloudflare.com"
        ]
        
        # 速度测试文件
        self.speedtest_url = "https://speed.cloudflare.com/__down?bytes=500000"  # 500KB
        
    def setup_v2ray(self):
        """设置V2Ray环境"""
        if not os.path.exists(self.v2ray_path):
            print("❌ V2Ray未找到，请检查下载步骤")
            return False
        return True
    
    def parse_node_config(self, config):
        """解析节点配置"""
        try:
            if config.startswith('vmess://'):
                return self.parse_vmess(config)
            elif config.startswith('vless://'):
                return self.parse_vless(config)
            elif config.startswith('trojan://'):
                return self.parse_trojan(config)
            elif config.startswith('ss://'):
                return self.parse_ss(config)
            else:
                print(f"❌ 不支持的协议: {config[:50]}...")
                return None
        except Exception as e:
            print(f"❌ 解析配置失败: {e}")
            return None
    
    def parse_vmess(self, config):
        """解析VMess配置"""
        encoded = config[8:]
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding
        
        decoded = base64.b64decode(encoded).decode('utf-8')
        vmess = json.loads(decoded)
        
        v2ray_config = {
            "inbounds": [
                {
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "udp": True,
                        "auth": "noauth"
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": vmess.get("add"),
                                "port": int(vmess.get("port", 443)),
                                "users": [
                                    {
                                        "id": vmess.get("id"),
                                        "alterId": int(vmess.get("aid", 0)),
                                        "security": vmess.get("scy", "auto")
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": vmess.get("net", "tcp"),
                        "security": vmess.get("tls", ""),
                        "tlsSettings": {
                            "serverName": vmess.get("host", vmess.get("add"))
                        } if vmess.get("tls") else {},
                        "wsSettings": {
                            "path": vmess.get("path", ""),
                            "headers": {
                                "Host": vmess.get("host", "")
                            }
                        } if vmess.get("net") == "ws" else {}
                    }
                },
                {
                    "protocol": "freedom",
                    "tag": "direct"
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
        
        return v2ray_config
    
    def parse_vless(self, config):
        """解析VLESS配置"""
        parsed = urlparse(config)
        user_id = parsed.username
        server = parsed.hostname
        port = parsed.port or 443
        
        params = {}
        for param in parsed.query.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
        
        v2ray_config = {
            "inbounds": [
                {
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "udp": True,
                        "auth": "noauth"
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": server,
                                "port": port,
                                "users": [
                                    {
                                        "id": user_id,
                                        "encryption": "none",
                                        "flow": params.get('flow', '')
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": params.get('type', 'tcp'),
                        "security": params.get('security', ''),
                        "tlsSettings": {
                            "serverName": params.get('sni', server)
                        } if params.get('security') == 'tls' else {},
                        "wsSettings": {
                            "path": params.get('path', ''),
                            "headers": {
                                "Host": params.get('host', server)
                            }
                        } if params.get('type') == 'ws' else {}
                    }
                },
                {
                    "protocol": "freedom",
                    "tag": "direct"
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
        
        return v2ray_config
    
    def parse_trojan(self, config):
        """解析Trojan配置"""
        parsed = urlparse(config)
        password = parsed.username
        server = parsed.hostname
        port = parsed.port or 443
        
        v2ray_config = {
            "inbounds": [
                {
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "udp": True,
                        "auth": "noauth"
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": server,
                                "port": port,
                                "password": password
                            }
                        ]
                    },
                    "streamSettings": {
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": server
                        }
                    }
                },
                {
                    "protocol": "freedom",
                    "tag": "direct"
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
        
        return v2ray_config
    
    def parse_ss(self, config):
        """解析Shadowsocks配置"""
        if '@' in config:
            method_password = config[5:].split('@')[0]
            server_port = config.split('@')[1].split('#')[0]
            
            if ':' in method_password and ':' in server_port:
                method, password_encoded = method_password.split(':', 1)
                server, port = server_port.split(':', 1)
                
                # Base64解码
                padding = 4 - len(password_encoded) % 4
                if padding != 4:
                    password_encoded += '=' * padding
                password = base64.b64decode(password_encoded).decode('utf-8')
                
                v2ray_config = {
                    "inbounds": [
                        {
                            "port": self.local_port,
                            "listen": "127.0.0.1",
                            "protocol": "socks",
                            "settings": {
                                "udp": True,
                                "auth": "noauth"
                            }
                        }
                    ],
                    "outbounds": [
                        {
                            "protocol": "shadowsocks",
                            "settings": {
                                "servers": [
                                    {
                                        "address": server,
                                        "port": int(port),
                                        "method": method,
                                        "password": password
                                    }
                                ]
                            }
                        },
                        {
                            "protocol": "freedom",
                            "tag": "direct"
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
                
                return v2ray_config
        
        return None
    
    def start_v2ray(self, config):
        """启动V2Ray进程"""
        try:
            # 保存配置
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # 启动V2Ray
            self.v2ray_process = subprocess.Popen(
                [self.v2ray_path, "run", "-config", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # 等待V2Ray启动
            time.sleep(3)
            
            # 检查进程是否运行
            if self.v2ray_process.poll() is not None:
                stdout, stderr = self.v2ray_process.communicate()
                print(f"❌ V2Ray启动失败: {stderr.decode()}")
                return False
            
            print("✅ V2Ray启动成功")
            return True
            
        except Exception as e:
            print(f"❌ 启动V2Ray失败: {e}")
            return False
    
    def stop_v2ray(self):
        """停止V2Ray进程"""
        if self.v2ray_process:
            try:
                self.v2ray_process.terminate()
                self.v2ray_process.wait(timeout=5)
                print("✅ V2Ray已停止")
            except:
                self.v2ray_process.kill()
            self.v2ray_process = None
    
    def test_connectivity(self, proxy_url):
        """测试连接性"""
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        
        success_count = 0
        total_latency = 0
        max_retries = 2
        
        for test_url in self.test_urls:
            for attempt in range(max_retries):
                try:
                    start_time = time.time()
                    response = requests.get(
                        test_url,
                        proxies=proxies,
                        timeout=10,
                        verify=False
                    )
                    latency = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        success_count += 1
                        total_latency += latency
                        print(f"  ✅ {test_url} - {latency:.1f}ms")
                        break
                    else:
                        print(f"  ❌ {test_url} - HTTP {response.status_code}")
                        
                except Exception as e:
                    if attempt == max_retries - 1:
                        print(f"  ❌ {test_url} - {str(e)}")
                    time.sleep(1)
        
        avg_latency = total_latency / success_count if success_count > 0 else 0
        success_rate = (success_count / len(self.test_urls)) * 100
        
        return success_rate, avg_latency
    
    def test_speed(self, proxy_url):
        """测试下载速度"""
        try:
            start_time = time.time()
            response = requests.get(
                self.speedtest_url,
                proxies={'http': proxy_url, 'https': proxy_url},
                timeout=15,
                stream=True,
                verify=False
            )
            
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if time.time() - start_time > 10:  # 最多下载10秒
                    break
                if total_size > 500000:  # 下载500KB
                    break
            
            download_time = time.time() - start_time
            
            if download_time > 0 and total_size > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                return True, speed_mbps, total_size
            else:
                return False, 0, 0
                
        except Exception as e:
            return False, 0, 0
    
    def test_single_node(self, node_config, index):
        """测试单个节点"""
        print(f"\n🔍 测试节点 {index}: {node_config[:80]}...")
        
        # 解析配置
        v2ray_config = self.parse_node_config(node_config)
        if not v2ray_config:
            return None
        
        # 启动V2Ray
        if not self.start_v2ray(v2ray_config):
            return None
        
        proxy_url = f"socks5://127.0.0.1:{self.local_port}"
        result = {
            'config': node_config,
            'index': index,
            'success': False,
            'connectivity_rate': 0,
            'latency': 0,
            'speed_mbps': 0,
            'error': ''
        }
        
        try:
            # 测试连接性
            connectivity_rate, avg_latency = self.test_connectivity(proxy_url)
            result['connectivity_rate'] = connectivity_rate
            result['latency'] = avg_latency
            
            # 测试速度
            speed_success, speed_mbps, downloaded_size = self.test_speed(proxy_url)
            result['speed_mbps'] = speed_mbps
            
            # 判断是否成功
            if connectivity_rate >= 60 and speed_mbps > 0.1:
                result['success'] = True
                print(f"✅ 节点测试成功 - 连通率: {connectivity_rate:.1f}%, 延迟: {avg_latency:.1f}ms, 速度: {speed_mbps:.2f} Mbps")
            else:
                print(f"❌ 节点测试失败 - 连通率: {connectivity_rate:.1f}%, 速度: {speed_mbps:.2f} Mbps")
                
        except Exception as e:
            result['error'] = str(e)
            print(f"❌ 测试过程中出错: {e}")
        
        finally:
            self.stop_v2ray()
            time.sleep(1)  # 等待端口释放
        
        return result
    
    def read_nodes(self, filename="ping.txt"):
        """读取节点列表"""
        if not os.path.exists(filename):
            print(f"❌ 找不到节点文件: {filename}")
            return []
        
        nodes = []
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    nodes.append(line)
        
        print(f"📋 读取到 {len(nodes)} 个节点")
        return nodes
    
    def run_tests(self):
        """运行所有测试"""
        if not self.setup_v2ray():
            return []
        
        nodes = self.read_nodes()
        if not nodes:
            return []
        
        results = []
        valid_nodes = []
        
        for i, node_config in enumerate(nodes, 1):
            result = self.test_single_node(node_config, i)
            if result:
                results.append(result)
                if result['success']:
                    valid_nodes.append(node_config)
            
            # GitHub Actions限制，避免超时
            if i % 10 == 0:
                print(f"⏳ 已完成 {i}/{len(nodes)} 个节点测试")
        
        # 按速度排序
        valid_results = [r for r in results if r['success']]
        valid_results.sort(key=lambda x: x['speed_mbps'], reverse=True)
        
        # 保存结果
        self.save_results(valid_results, valid_nodes)
        
        return valid_results
    
    def save_results(self, results, valid_nodes):
        """保存测试结果"""
        # 保存有效的节点配置
        with open('ping.txt', 'w', encoding='utf-8') as f:
            for node in valid_nodes:
                f.write(node + '\n')
        
        # 保存详细结果
        result_data = {
            'timestamp': time.time(),
            'total_tested': len(results),
            'valid_nodes': len(valid_nodes),
            'results': results
        }
        
        with open('results.json', 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n📊 测试完成:")
        print(f"总测试节点: {len(results)}")
        print(f"有效节点: {len(valid_nodes)}")
        
        if valid_nodes:
            print(f"\n🏆 速度排名前10:")
            for i, result in enumerate(results[:10], 1):
                print(f"{i:2d}. 速度: {result['speed_mbps']:.2f} Mbps, 延迟: {result['latency']:.1f}ms")

def main():
    """主函数"""
    tester = GitHubV2RayTester()
    
    try:
        start_time = time.time()
        results = tester.run_tests()
        end_time = time.time()
        
        print(f"\n⏱️ 总耗时: {end_time - start_time:.2f}秒")
        
    except Exception as e:
        print(f"❌ 测试出错: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
