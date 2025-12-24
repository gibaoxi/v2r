import subprocess
import json
import time
import os
import tempfile
import base64
import re
from urllib.parse import urlparse

class V2RayTester:
    def __init__(self):
        self.v2ray_bin = "v2ray"  # v2ray命令行工具
        self.test_url = "https://github.com/"
    
    def parse_proxy_link(self, link):
        """解析代理链接为v2ray配置"""
        if link.startswith('vmess://'):
            return self._parse_vmess(link)
        elif link.startswith('ss://'):
            return self._parse_ss(link)
        elif link.startswith('trojan://'):
            return self._parse_trojan(link)
        elif link.startswith('vless://'):
            return self._parse_vless(link)
        else:
            return None
    
    def _parse_vmess(self, link):
        """解析vmess链接"""
        try:
            # 移除vmess://前缀
            encoded = link[8:]
            # 补齐base64填充
            padded = encoded + '=' * (4 - len(encoded) % 4)
            decoded = base64.b64decode(padded).decode('utf-8')
            config = json.loads(decoded)
            
            v2ray_config = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": config.get("add"),
                        "port": int(config.get("port", 443)),
                        "users": [{
                            "id": config.get("id"),
                            "alterId": config.get("aid", 0),
                            "security": config.get("scy", "auto")
                        }]
                    }]
                },
                "streamSettings": {
                    "network": config.get("net", "tcp"),
                    "security": config.get("tls", ""),
                    "wsSettings": config.get("wsSettings", {}),
                    "tcpSettings": config.get("tcpSettings", {}),
                    "kcpSettings": config.get("kcpSettings", {}),
                    "httpSettings": config.get("httpSettings", {})
                }
            }
            
            # 设置sni
            if config.get("sni"):
                v2ray_config["streamSettings"]["tlsSettings"] = {
                    "serverName": config.get("sni")
                }
            
            return v2ray_config
        except Exception as e:
            print(f"解析vmess失败: {e}")
            return None
    
    def _parse_ss(self, link):
        """解析ss链接"""
        try:
            # ss://method:password@host:port#remark
            parsed = urlparse(link)
            userinfo = parsed.netloc.split('@')[0]
            server_part = parsed.netloc.split('@')[1]
            
            # 解码base64
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                decoded = base64.b64decode(userinfo + '=' * (4 - len(userinfo) % 4)).decode()
                method, password = decoded.split(':', 1)
            
            host, port = server_part.split(':')
            
            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": int(port),
                        "method": method,
                        "password": password
                    }]
                }
            }
        except Exception as e:
            print(f"解析ss失败: {e}")
            return None
    
    def _parse_trojan(self, link):
        """解析trojan链接"""
        try:
            # trojan://password@host:port#remark
            parsed = urlparse(link)
            password = parsed.netloc.split('@')[0]
            server_part = parsed.netloc.split('@')[1]
            host, port = server_part.split(':')
            
            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": int(port),
                        "password": password
                    }]
                },
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": host
                    }
                }
            }
        except Exception as e:
            print(f"解析trojan失败: {e}")
            return None
    
    def _parse_vless(self, link):
        """解析vless链接"""
        try:
            # vless://uuid@host:port?type=ws&security=tls#remark
            parsed = urlparse(link)
            userinfo = parsed.netloc.split('@')[0]
            server_part = parsed.netloc.split('@')[1]
            host, port = server_part.split(':')
            
            query_params = {}
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
            
            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": int(port),
                        "users": [{
                            "id": userinfo,
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": query_params.get("type", "tcp"),
                    "security": query_params.get("security", "")
                }
            }
        except Exception as e:
            print(f"解析vless失败: {e}")
            return None
    
    def create_v2ray_config(self, outbound_config, local_port=1080):
        """创建完整的v2ray配置文件"""
        return {
            "inbounds": [{
                "port": local_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "tag": "socks-inbound"
            }],
            "outbounds": [outbound_config, {
                "protocol": "freedom",
                "tag": "direct"
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
    
    def test_proxy_latency(self, link):
        """测试单个代理的延迟"""
        outbound_config = self.parse_proxy_link(link)
        if not outbound_config:
            return None
        
        # 创建临时配置文件
        config = self.create_v2ray_config(outbound_config)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f, indent=2)
            config_file = f.name
        
        try:
            # 启动v2ray
            process = subprocess.Popen(
                [self.v2ray_bin, 'run', '-config', config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 等待v2ray启动
            time.sleep(3)
            
            # 测试延迟
            start_time = time.time()
            curl_result = subprocess.run([
                'curl', '-x', 'socks5://127.0.0.1:1080',
                '--connect-timeout', '10',
                '--max-time', '15',
                '-s', '-o', '/dev/null', '-w', '%{http_code}',
                self.test_url
            ], capture_output=True, text=True, timeout=20)
            
            latency = (time.time() - start_time) * 1000
            
            # 停止v2ray
            process.terminate()
            process.wait(timeout=5)
            
            if curl_result.returncode == 0 and curl_result.stdout.strip() == '200':
                return latency
            else:
                return None
                
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            print(f"测试错误: {e}")
            return None
        finally:
            # 清理临时文件
            try:
                os.unlink(config_file)
            except:
                pass
            # 确保v2ray进程被终止
            try:
                process.terminate()
            except:
                pass

def main():
    print("v2ray代理延迟测试")
    print("=" * 50)
    
    # 读取代理链接
    try:
        with open('all_configs.txt', 'r', encoding='utf-8') as f:
            links = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("错误: 找不到 sub.txt 文件")
        return
    
    if not links:
        print("错误: sub.txt 中没有代理链接")
        return
    
    print(f"找到 {len(links)} 个代理链接")
    
    tester = V2RayTester()
    results = []
    
    for i, link in enumerate(links, 1):
        print(f"测试 [{i}/{len(links)}]: {link[:60]}...")
        
        latency = tester.test_proxy_latency(link)
        if latency is not None:
            results.append((latency, link))
    
    # 按延迟排序
    results.sort(key=lambda x: x[0])
    
    # 写入结果
    with open('res.txt', 'w', encoding='utf-8') as f:
        for latency, link in results:
            f.write(f"{link}\n")
    
    print(f"\n测试完成! 可用代理: {len(results)}/{len(links)}")
    if results:
        print("最快的3个代理:")
        for i, (latency, link) in enumerate(results[:3], 1):
            print(f"{i}. {latency:.1f}ms - {link[:50]}...")

if __name__ == "__main__":
    main()
