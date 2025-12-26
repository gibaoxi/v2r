#!/usr/bin/env python3
import os
import sys
import time
import json
import requests
import subprocess
import base64
import socket
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
        
        self.test_urls = ["http://httpbin.org/ip", "http://ifconfig.me"]  # 使用HTTP测试
        self.speedtest_url = "http://speedtest.ftp.otenet.gr/files/test1Mb.db"  # 使用HTTP速度测试
        
    def check_port_available(self, port):
        """检查端口是否可用"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def wait_for_port(self, port, timeout=10):
        """等待端口就绪"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.check_port_available(port):
                return True
            time.sleep(0.5)
        return False
    
    def setup_v2ray(self):
        """检查V2Ray环境"""
        if not os.path.exists(self.v2ray_path):
            print(f"❌ V2Ray文件不存在: {self.v2ray_path}")
            return False
        
        # 设置执行权限
        os.chmod(self.v2ray_path, 0o755)
        
        # 测试V2Ray版本
        try:
            result = subprocess.run(
                [self.v2ray_path, "-version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            print("✅ V2Ray准备就绪")
            if result.stdout:
                print(f"  版本信息: {result.stdout.strip()}")
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
            
            # 简化配置，确保基本功能
            v2ray_config = {
                "log": {
                    "loglevel": "warning"
                },
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False  # 先禁用UDP简化测试
                    },
                    "sniffing": {
                        "enabled": False
                    }
                }],
                "outbounds": [{
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": vmess["add"],
                            "port": int(vmess["port"]),
                            "users": [{
                                "id": vmess["id"],
                                "alterId": int(vmess.get("aid", 0)),
                                "security": vmess.get("scy", "auto")
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": vmess.get("net", "tcp"),
                        "security": vmess.get("tls", "none")
                    },
                    "tag": "proxy"
                }, {
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": {}
                }],
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [{
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct"
                    }]
                }
            }
            
            # 添加WebSocket设置
            if vmess.get("net") == "ws":
                v2ray_config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                    "path": vmess.get("path", ""),
                    "headers": {
                        "Host": vmess.get("host", "")
                    }
                }
            
            # 添加TLS设置
            if vmess.get("tls"):
                v2ray_config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
                    "serverName": vmess.get("host", vmess.get("add"))
                }
            
            return v2ray_config
            
        except Exception as e:
            print(f"❌ 解析VMess失败: {e}")
            return None
    
    def parse_vless(self, config):
        """解析VLESS配置"""
        try:
            parsed = urlparse(config)
            params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p)
            
            v2ray_config = {
                "log": {
                    "loglevel": "warning"
                },
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False
                    }
                }],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": parsed.hostname,
                            "port": parsed.port or 443,
                            "users": [{
                                "id": parsed.username,
                                "encryption": "none",
                                "flow": params.get('flow', '')
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": params.get('type', 'tcp'),
                        "security": params.get('security', 'none')
                    },
                    "tag": "proxy"
                }],
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [{
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct"
                    }]
                }
            }
            
            if params.get('type') == 'ws':
                v2ray_config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                    "path": params.get('path', ''),
                    "headers": {
                        "Host": params.get('host', parsed.hostname)
                    }
                }
            
            if params.get('security') == 'tls':
                v2ray_config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get('sni', parsed.hostname)
                }
            
            return v2ray_config
            
        except Exception as e:
            print(f"❌ 解析VLESS失败: {e}")
            return None
    
    def parse_trojan(self, config):
        """解析Trojan配置"""
        try:
            parsed = urlparse(config)
            
            return {
                "log": {
                    "loglevel": "warning"
                },
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False
                    }
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
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": parsed.hostname
                        }
                    },
                    "tag": "proxy"
                }],
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [{
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct"
                    }]
                }
            }
        except Exception as e:
            print(f"❌ 解析Trojan失败: {e}")
            return None
    
    def parse_ss(self, config):
        """解析Shadowsocks配置"""
        try:
            config = config[5:]  # 移除ss://
            
            if '@' in config:
                parts = config.split('@')
                method_password = parts[0]
                server_port = parts[1].split('#')[0]
                
                method, password_encoded = method_password.split(':', 1)
                server, port_str = server_port.split(':', 1)
                
                # 尝试解码密码
                try:
                    padding = 4 - len(password_encoded) % 4
                    if padding != 4:
                        password_encoded += '=' * padding
                    password = base64.b64decode(password_encoded).decode('utf-8')
                except:
                    password = password_encoded
            else:
                # Base64编码格式
                padding = 4 - len(config) % 4
                if padding != 4:
                    config += '=' * padding
                decoded = base64.b64decode(config).decode('utf-8')
                
                if '@' in decoded:
                    parts = decoded.split('@')
                    method_password = parts[0]
                    server_port = parts[1]
                    
                    method, password = method_password.split(':', 1)
                    server, port_str = server_port.split(':', 1)
                else:
                    # cipher:password@server:port 格式
                    server_info = decoded.split('@')
                    if len(server_info) == 2:
                        method_password, server_port = server_info
                        method, password = method_password.split(':', 1)
                        server, port_str = server_port.split(':', 1)
                    else:
                        return None
            
            return {
                "log": {
                    "loglevel": "warning"
                },
                "inbounds": [{
                    "port": self.local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False
                    }
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
                    },
                    "tag": "proxy"
                }],
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [{
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct"
                    }]
                }
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
            
            # 确保端口空闲
            if self.check_port_available(self.local_port):
                print(f"⚠️ 端口 {self.local_port} 已被占用，等待释放...")
                time.sleep(2)
            
            # 启动V2Ray
            cmd = [self.v2ray_path, "run", "-config", self.config_path]
            print(f"🚀 启动V2Ray: {' '.join(cmd)}")
            
            self.v2ray_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 等待端口就绪
            if self.wait_for_port(self.local_port, timeout=10):
                print("✅ V2Ray启动成功，端口已就绪")
                return True
            else:
                # 检查进程输出
                try:
                    stdout, stderr = self.v2ray_process.communicate(timeout=1)
                    if stderr:
                        print(f"❌ V2Ray错误: {stderr.strip()}")
                    if stdout:
                        print(f"ℹ️ V2Ray输出: {stdout.strip()}")
                except:
                    pass
                
                print("❌ V2Ray启动失败：端口未就绪")
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
                print("✅ V2Ray已停止")
            except:
                try:
                    self.v2ray_process.kill()
                except:
                    pass
            self.v2ray_process = None
        
        # 清理配置文件
        if os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
            except:
                pass
        
        time.sleep(1)  # 等待端口释放
    
    def test_connectivity(self, proxy_url):
        """测试连接性"""
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        
        session = requests.Session()
        session.verify = False
        session.trust_env = False  # 避免系统代理干扰
        
        for test_url in self.test_urls:
            try:
                print(f"  🔗 测试连接: {test_url}")
                start_time = time.time()
                response = session.get(test_url, proxies=proxies, timeout=15)
                latency = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    print(f"  ✅ 连接成功 - {latency:.1f}ms")
                    try:
                        print(f"    响应: {response.text.strip()}")
                    except:
                        pass
                    return True, latency
                else:
                    print(f"  ❌ HTTP {response.status_code}")
                    
            except requests.exceptions.SSLError as e:
                print(f"  ❌ SSL错误: {e}")
            except requests.exceptions.ProxyError as e:
                print(f"  ❌ 代理错误: {e}")
            except requests.exceptions.ConnectTimeout as e:
                print(f"  ❌ 连接超时: {e}")
            except requests.exceptions.ConnectionError as e:
                print(f"  ❌ 连接错误: {e}")
            except Exception as e:
                print(f"  ❌ 请求错误: {e}")
        
        return False, 0
    
    def test_speed(self, proxy_url):
        """测试下载速度"""
        try:
            session = requests.Session()
            session.verify = False
            session.trust_env = False
            
            print(f"  🚀 开始速度测试...")
            start_time = time.time()
            response = session.get(
                self.speedtest_url,
                proxies={'http': proxy_url, 'https': proxy_url},
                timeout=30,
                stream=True
            )
            
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if time.time() - start_time > 15:  # 最多15秒
                    break
                if total_size > 5 * 1024 * 1024:  # 最多5MB
                    break
            
            download_time = time.time() - start_time
            
            if download_time > 0 and total_size > 0:
                speed_mbps = (total_size * 8) / (download_time * 1024 * 1024)
                print(f"  📊 下载 {total_size/1024:.1f}KB, 耗时 {download_time:.1f}s, 速度 {speed_mbps:.2f} Mbps")
                return True, speed_mbps, total_size
            else:
                print("  ❌ 速度测试失败")
                return False, 0, 0
                
        except Exception as e:
            print(f"  ❌ 速度测试错误: {e}")
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
            
            if i % 3 == 0:  # 每3个节点显示一次进度
                print(f"⏳ 已完成 {i}/{len(nodes)} 个节点测试")
                time.sleep(1)  # 短暂休息
        
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
