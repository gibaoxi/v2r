#!/usr/bin/env python3
import os
import sys
import time
import json
import requests
import subprocess
import base64
from urllib.parse import urlparse
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class GitHubV2RayTester:
    def __init__(self):
        self.v2ray_path = "./v2ray/v2ray"
        self.config_path = "./config.json"
        self.local_port = 10808
        self.v2ray_process = None
        
        self.test_urls = ["https://ip.sb"]
        self.speedtest_url = "https://speed.cloudflare.com/__down?bytes=1000000"
        
    def setup_v2ray(self):
        """检查V2Ray环境"""
        if not os.path.exists(self.v2ray_path):
            print(f"❌ V2Ray文件不存在: {self.v2ray_path}")
            return False
        
        # 设置执行权限
        os.chmod(self.v2ray_path, 0o755)
        
        # 测试V2Ray版本和参数
        try:
            result = subprocess.run(
                [self.v2ray_path, "-h"],
                capture_output=True,
                text=True,
                timeout=5
            )
            print("✅ V2Ray准备就绪")
            return True
        except Exception as e:
            print(f"❌ V2Ray测试失败: {e}")
            return False
    
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
                print(f"❌ 不支持的协议")
                return None
        except Exception as e:
            print(f"❌ 解析配置失败: {e}")
            return None
    
    def parse_vmess(self, config):
        """解析VMess配置"""
        try:
            encoded = config[8:]
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            
            decoded = base64.b64decode(encoded).decode('utf-8')
            vmess = json.loads(decoded)
            
            return {
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True, "auth": "noauth"}
                }],
                "outbounds": [{
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": vmess["add"],
                            "port": int(vmess["port"]),
                            "users": [{
                                "id": vmess["id"],
                                "alterId": int(vmess.get("aid", 0))
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": vmess.get("net", "tcp")
                    }
                }]
            }
        except Exception as e:
            print(f"❌ 解析VMess失败: {e}")
            return None
    
    def parse_vless(self, config):
        """解析VLESS配置"""
        try:
            parsed = urlparse(config)
            params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p)
            
            return {
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True, "auth": "noauth"}
                }],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": parsed.hostname,
                            "port": parsed.port or 443,
                            "users": [{"id": parsed.username, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": {
                        "network": params.get('type', 'tcp')
                    }
                }]
            }
        except Exception as e:
            print(f"❌ 解析VLESS失败: {e}")
            return None
    
    def parse_trojan(self, config):
        """解析Trojan配置"""
        try:
            parsed = urlparse(config)
            
            return {
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True, "auth": "noauth"}
                }],
                "outbounds": [{
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": parsed.hostname,
                            "port": parsed.port or 443,
                            "password": parsed.username
                        }]
                    },
                    "streamSettings": {
                        "security": "tls"
                    }
                }]
            }
        except Exception as e:
            print(f"❌ 解析Trojan失败: {e}")
            return None
    
    def parse_ss(self, config):
        """解析Shadowsocks配置"""
        try:
            if '@' not in config:
                return None
                
            parts = config[5:].split('@')
            method_password = parts[0]
            server_port = parts[1].split('#')[0]
            
            method, password_encoded = method_password.split(':', 1)
            server, port_str = server_port.split(':', 1)
            
            padding = 4 - len(password_encoded) % 4
            if padding != 4:
                password_encoded += '=' * padding
            password = base64.b64decode(password_encoded).decode('utf-8')
            
            return {
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True, "auth": "noauth"}
                }],
                "outbounds": [{
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": server,
                            "port": int(port_str),
                            "method": method,
                            "password": password
                        }]
                    }
                }]
            }
        except Exception as e:
            print(f"❌ 解析SS失败: {e}")
            return None
    
    def start_v2ray(self, config):
        """启动V2Ray进程"""
        try:
            # 保存配置
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # 尝试不同的参数格式
            command_formats = [
                [self.v2ray_path, "run", "-config", self.config_path],  # 新版本格式
                [self.v2ray_path, "-config", self.config_path],         # 旧版本格式
                [self.v2ray_path, "run", "-c", self.config_path],      # 短参数格式
                [self.v2ray_path, "-c", self.config_path]             # 短参数旧格式
            ]
            
            for cmd in command_formats:
                try:
                    print(f"🚀 尝试启动命令: {' '.join(cmd)}")
                    self.v2ray_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                    # 等待启动
                    time.sleep(3)
                    
                    # 检查进程状态
                    if self.v2ray_process.poll() is not None:
                        stdout, stderr = self.v2ray_process.communicate()
                        error_msg = stderr.decode() if stderr else stdout.decode()
                        print(f"❌ 启动失败: {error_msg}")
                        continue
                    
                    print("✅ V2Ray启动成功")
                    return True
                    
                except Exception as e:
                    print(f"❌ 命令失败: {e}")
                    if self.v2ray_process:
                        self.v2ray_process.terminate()
                        self.v2ray_process = None
                    continue
            
            print("❌ 所有启动方式都失败了")
            return False
            
        except Exception as e:
            print(f"❌ 启动V2Ray失败: {e}")
            return False
    
    def stop_v2ray(self):
        """停止V2Ray进程"""
        if self.v2ray_process:
            try:
                self.v2ray_process.terminate()
                self.v2ray_process.wait(timeout=3)
            except:
                try:
                    self.v2ray_process.kill()
                except:
                    pass
            self.v2ray_process = None
        
        if os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
            except:
                pass
    
    def test_connectivity(self, proxy_url):
        """测试连接性"""
        proxies = {'http': proxy_url, 'https': proxy_url}
        
        for test_url in self.test_urls:
            try:
                start_time = time.time()
                response = requests.get(test_url, proxies=proxies, timeout=10, verify=False)
                latency = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    print(f"  ✅ 连接成功 - {latency:.1f}ms")
                    return True, latency
                else:
                    print(f"  ❌ HTTP {response.status_code}")
                    
            except Exception as e:
                print(f"  ❌ 连接失败: {str(e)}")
        
        return False, 0
    
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
                if time.time() - start_time > 10:
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
        print(f"\n🔍 测试节点 {index}: {node_config[:50]}...")
        
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
            'latency': 0,
            'speed_mbps': 0
        }
        
        try:
            # 测试连接性
            connectivity, latency = self.test_connectivity(proxy_url)
            result['latency'] = latency
            
            if connectivity:
                # 测试速度
                speed_success, speed_mbps, _ = self.test_speed(proxy_url)
                result['speed_mbps'] = speed_mbps
                
                if speed_mbps > 0.1:
                    result['success'] = True
                    print(f"✅ 节点测试成功 - 延迟: {latency:.1f}ms, 速度: {speed_mbps:.2f} Mbps")
                else:
                    print(f"❌ 节点速度太慢")
            else:
                print(f"❌ 节点连接失败")
                
        except Exception as e:
            print(f"❌ 测试出错: {e}")
        
        finally:
            self.stop_v2ray()
            time.sleep(1)
        
        return result
    
    def read_nodes(self, filename="sub.txt"):
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
            
            if i % 5 == 0:
                print(f"⏳ 已完成 {i}/{len(nodes)} 个节点测试")
        
        # 保存有效节点
        with open('ping.txt', 'w', encoding='utf-8') as f:
            for node in valid_nodes:
                f.write(node + '\n')
        
        print(f"\n📊 测试完成: 总测试 {len(nodes)} 个节点, 有效 {len(valid_nodes)} 个")
        
        if valid_nodes:
            print("🏆 速度排名:")
            valid_results = [r for r in results if r['success']]
            valid_results.sort(key=lambda x: x['speed_mbps'], reverse=True)
            
            for i, result in enumerate(valid_results[:10], 1):
                print(f"{i:2d}. 速度: {result['speed_mbps']:.2f} Mbps, 延迟: {result['latency']:.1f}ms")
        
        return results

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
