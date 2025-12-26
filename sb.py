#!/usr/bin/env python3
import socket
import time
import json
import subprocess
import requests
from urllib.parse import urlparse, parse_qs
import base64
import os
import concurrent.futures
import threading
import shutil
import re
import logging
from typing import List, Dict, Any, Optional, Tuple

# ========== 配置区域 ==========
# 测试参数
BATCH_SIZE = 2                    # 同时测试的最大节点数
SERIAL_DOWNLOAD = True           # 串行下载测试（避免带宽竞争）
MAX_TEST_TIME = 300              # 最大测试时间（秒）

# 路径配置
SINGBOX_BIN = "./sing-box/sing-box"
CONFIG_DIR = "./temp_configs"
SOCKS_PORT_START = 10808

# 测试端点
HTTP_TEST_URLS = [
    "https://www.google.com",
    "https://cloudflare.com",
    "https://www.bing.com"
]

DOWNLOAD_URLS = [
    "https://speed.cloudflare.com/__down?bytes=1048576",  # 1MB
    "https://dl.google.com/dl/android/aosp/sailfish-qq1a.191205.008-factory-295a07b3.zip"  # 小文件
]

# 超时设置
TCP_TIMEOUT = 8
HTTP_TIMEOUT = 12
DOWNLOAD_TIMEOUT = 20

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 创建临时目录
os.makedirs(CONFIG_DIR, exist_ok=True)

class NodeTester:
    """Sing-box节点测试器"""
    
    def __init__(self):
        self.results = []
        self.start_time = time.time()
        
    def check_singbox(self) -> bool:
        """检查Sing-box是否可用"""
        try:
            result = subprocess.run([SINGBOX_BIN, "version"], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"✅ Sing-box版本: {result.stdout.strip()}")
            return True
        except Exception as e:
            logger.error(f"❌ Sing-box不可用: {e}")
            return False
    
    def parse_node(self, line: str) -> Optional[Dict[str, Any]]:
        """解析节点链接"""
        line = line.strip()
        if not line:
            return None
            
        try:
            if line.startswith("vless://"):
                return self._parse_vless(line)
            elif line.startswith("trojan://"):
                return self._parse_trojan(line)
            elif line.startswith("vmess://"):
                return self._parse_vmess(line)
            elif line.startswith("ss://"):
                return self._parse_ss(line)
            elif line.startswith("hysteria2://") or line.startswith("hy2://"):
                return self._parse_hysteria2(line)
            else:
                logger.warning(f"未知协议: {line[:50]}...")
                return None
        except Exception as e:
            logger.error(f"解析节点失败 {line[:30]}...: {e}")
            return None
    
    def _parse_vless(self, line: str) -> Dict[str, Any]:
        """解析VLESS链接"""
        u = urlparse(line)
        q = parse_qs(u.query)
        
        return {
            "type": "vless",
            "server": u.hostname,
            "port": u.port or 443,
            "uuid": u.username,
            "network": q.get("type", ["tcp"])[0],
            "security": q.get("security", [""])[0],
            "sni": q.get("sni", [u.hostname])[0],
            "host": q.get("host", [u.hostname])[0],
            "path": q.get("path", [""])[0],
            "publicKey": q.get("pbk", [""])[0],
            "shortId": q.get("sid", [""])[0],
        }
    
    def _parse_trojan(self, line: str) -> Dict[str, Any]:
        """解析Trojan链接"""
        u = urlparse(line)
        return {
            "type": "trojan",
            "server": u.hostname,
            "port": u.port or 443,
            "password": u.username,
        }
    
    def _parse_vmess(self, line: str) -> Dict[str, Any]:
        """解析VMess链接"""
        try:
            # 移除vmess://前缀并解码
            data = base64.b64decode(line[8:] + "==").decode('utf-8')
            j = json.loads(data)
            
            return {
                "type": "vmess",
                "server": j["add"],
                "port": int(j["port"]),
                "uuid": j["id"],
                "network": j.get("net", "tcp"),
                "host": j.get("host", ""),
                "path": j.get("path", ""),
                "tls": j.get("tls", "")
            }
        except Exception as e:
            logger.error(f"VMess解析失败: {e}")
            return None
    
    def _parse_ss(self, line: str) -> Dict[str, Any]:
        """解析Shadowsocks链接"""
        # 移除注释
        clean_line = line.split('#')[0]
        
        # 提取Base64部分
        if '@' not in clean_line[5:]:
            # 整个链接是Base64编码的
            try:
                base64_part = clean_line[5:]
                padding = (4 - len(base64_part) % 4) % 4
                decoded = base64.b64decode(base64_part + '=' * padding).decode('utf-8')
                clean_line = "ss://" + decoded
            except:
                return None
        
        # 解析标准格式
        try:
            method_password, server_part = clean_line[5:].split('@', 1)
            
            # 解码方法和密码
            if ':' not in method_password:
                return None
            method, password = method_password.split(':', 1)
            
            # 解析服务器和端口
            server_part = server_part.split('/')[0]  # 移除路径
            if ':' not in server_part:
                return None
                
            server, port_str = server_part.rsplit(':', 1)
            port = int(port_str)
            
            return {
                "type": "ss",
                "server": server,
                "port": port,
                "method": method,
                "password": password
            }
        except Exception as e:
            logger.error(f"SS解析失败: {e}")
            return None
    
    def _parse_hysteria2(self, line: str) -> Dict[str, Any]:
        """解析Hysteria2链接"""
        try:
            # 移除协议头
            clean_line = line.replace('hysteria2://', '').replace('hy2://', '')
            clean_line = clean_line.split('#')[0]  # 移除注释
            
            if '@' not in clean_line:
                return None
                
            uuid, server_part = clean_line.split('@', 1)
            if ':' not in server_part:
                return None
                
            server, port = server_part.split(':', 1)
            
            return {
                "type": "hysteria2",
                "server": server,
                "port": int(port),
                "uuid": uuid
            }
        except Exception as e:
            logger.error(f"Hysteria2解析失败: {e}")
            return None
    
    def tcp_test(self, host: str, port: int) -> Tuple[bool, int]:
        """TCP连接测试"""
        try:
            start = time.time()
            sock = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
            sock.close()
            delay = int((time.time() - start) * 1000)
            return True, delay
        except Exception as e:
            return False, -1
    
    def http_test(self, socks_port: int) -> Tuple[bool, int]:
        """HTTP可访问性测试"""
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}"
        }
        
        for url in HTTP_TEST_URLS:
            try:
                start_time = time.time()
                response = requests.get(url, proxies=proxies, timeout=HTTP_TIMEOUT)
                delay = int((time.time() - start_time) * 1000)
                
                if response.status_code in (200, 204):
                    return True, delay
            except:
                continue
                
        return False, -1
    
    def speed_test(self, socks_port: int) -> Tuple[float, float]:
        """下载速度测试"""
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}"
        }
        
        for download_url in DOWNLOAD_URLS:
            try:
                start_time = time.time()
                response = requests.get(download_url, proxies=proxies, 
                                      stream=True, timeout=DOWNLOAD_TIMEOUT)
                size = 0
                download_start = time.time()
                
                for chunk in response.iter_content(8192):
                    size += len(chunk)
                    if size >= 1048576:  # 下载1MB后停止
                        break
                
                download_time = time.time() - download_start
                if download_time > 0:
                    speed = (size * 8) / (download_time * 1024 * 1024)  # Mbps
                    return round(speed, 2), round(download_time, 2)
                    
            except:
                continue
                
        return 0.0, -1
    
    def generate_singbox_config(self, node: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
        """生成Sing-box配置"""
        outbound = self._create_outbound(node)
        
        return {
            "log": {
                "level": "error",
                "timestamp": True
            },
            "dns": {
                "servers": [
                    {"address": "tls://1.1.1.1"},
                    {"address": "tls://8.8.8.8"}
                ],
                "strategy": "ipv4_first"
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": socks_port,
                    "sniff": True
                }
            ],
            "outbounds": [
                outbound,
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block", 
                    "tag": "block"
                }
            ],
            "route": {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "direct"
                    },
                    {
                        "network": "udp",
                        "port": 53,
                        "outbound": "direct"
                    }
                ],
                "auto_detect_interface": True,
                "final": "proxy"
            }
        }
    
    def _create_outbound(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """创建出站配置"""
        node_type = node["type"]
        
        if node_type == "vless":
            return self._create_vless_outbound(node)
        elif node_type == "trojan":
            return self._create_trojan_outbound(node)
        elif node_type == "vmess":
            return self._create_vmess_outbound(node)
        elif node_type == "ss":
            return self._create_ss_outbound(node)
        elif node_type == "hysteria2":
            return self._create_hysteria2_outbound(node)
        else:
            return {"type": "direct"}
    
    def _create_vless_outbound(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """创建VLESS出站配置"""
        outbound = {
            "type": "vless",
            "server": node["server"],
            "server_port": node["port"],
            "uuid": node["uuid"],
            "flow": ""
        }
        
        # 传输设置
        network = node.get("network", "tcp")
        if network != "tcp":
            outbound["transport"] = {"type": network}
            if network == "ws":
                outbound["transport"].update({
                    "path": node.get("path", ""),
                    "headers": {"Host": node.get("host", node["server"])}
                })
            elif network == "grpc":
                outbound["transport"]["service_name"] = node.get("path", "")
        
        # 安全设置
        security = node.get("security", "")
        if security in ["tls", "reality"]:
            outbound["tls"] = {
                "enabled": True,
                "server_name": node.get("sni", node["server"]),
                "insecure": False
            }
            if security == "reality":
                outbound["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": node.get("publicKey", ""),
                    "short_id": node.get("shortId", "")
                }
        
        return outbound
    
    def _create_trojan_outbound(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """创建Trojan出站配置"""
        return {
            "type": "trojan",
            "server": node["server"],
            "server_port": node["port"],
            "password": node["password"],
            "tls": {
                "enabled": True,
                "server_name": node["server"],
                "insecure": False
            }
        }
    
    def _create_vmess_outbound(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """创建VMess出站配置"""
        outbound = {
            "type": "vmess",
            "server": node["server"],
            "server_port": node["port"],
            "uuid": node["uuid"],
            "security": "auto"
        }
        
        if node.get("tls") == "tls":
            outbound["tls"] = {
                "enabled": True,
                "server_name": node["server"],
                "insecure": False
            }
        
        network = node.get("network", "tcp")
        if network != "tcp":
            outbound["transport"] = {"type": network}
            if network == "ws":
                outbound["transport"].update({
                    "path": node.get("path", ""),
                    "headers": {"Host": node.get("host", node["server"])}
                })
        
        return outbound
    
    def _create_ss_outbound(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """创建Shadowsocks出站配置"""
        return {
            "type": "shadowsocks",
            "server": node["server"],
            "server_port": node["port"],
            "method": node["method"],
            "password": node["password"]
        }
    
    def _create_hysteria2_outbound(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """创建Hysteria2出站配置"""
        return {
            "type": "hysteria2",
            "server": node["server"],
            "server_port": node["port"],
            "password": node["uuid"],
            "tls": {
                "enabled": True,
                "server_name": node["server"],
                "insecure": False
            }
        }
    
    def run_singbox_instance(self, config_path: str, socks_port: int) -> Optional[subprocess.Popen]:
        """运行Sing-box实例"""
        try:
            process = subprocess.Popen(
                [SINGBOX_BIN, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(3)  # 等待启动
            return process
        except Exception as e:
            logger.error(f"启动Sing-box失败: {e}")
            return None
    
    def stop_singbox_instance(self, process: subprocess.Popen):
        """停止Sing-box实例"""
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            try:
                process.kill()
            except:
                pass
    
    def batch_tcp_test(self, nodes: List[Tuple[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """批量TCP测试"""
        logger.info(f"开始TCP测试 ({len(nodes)}个节点)...")
        
        def test_single(args):
            i, (line, node) = args
            if time.time() - self.start_time > MAX_TEST_TIME:
                return None
                
            tcp_ok, tcp_ms = self.tcp_test(node["server"], node["port"])
            result = {
                "id": i,
                "line": line,
                "node": node,
                "tcp_ok": tcp_ok,
                "tcp_ms": tcp_ms
            }
            
            if tcp_ok:
                logger.info(f"✅ TCP成功: {node['server']}:{node['port']} ({tcp_ms}ms)")
            else:
                logger.info(f"❌ TCP失败: {node['server']}:{node['port']}")
                
            return result
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            results = list(executor.map(test_single, enumerate(nodes)))
        
        # 过滤None结果（超时情况）
        results = [r for r in results if r is not None]
        results.sort(key=lambda x: x["id"])
        
        success_count = sum(1 for r in results if r["tcp_ok"])
        logger.info(f"TCP测试完成: {success_count}/{len(nodes)} 成功")
        
        return results
    
    def batch_http_test(self, tcp_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量HTTP测试"""
        http_nodes = [(r["line"], r["node"], r["id"]) for r in tcp_results if r["tcp_ok"]]
        
        if not http_nodes:
            logger.warning("没有通过TCP测试的节点，跳过HTTP测试")
            return []
        
        logger.info(f"开始HTTP测试 ({len(http_nodes)}个节点)...")
        results = []
        
        # 分批测试
        for i in range(0, len(http_nodes), BATCH_SIZE):
            if time.time() - self.start_time > MAX_TEST_TIME:
                break
                
            batch = http_nodes[i:i+BATCH_SIZE]
            batch_results = self._test_http_batch(batch, i // BATCH_SIZE + 1)
            results.extend(batch_results)
        
        results.sort(key=lambda x: x["id"])
        success_count = sum(1 for r in results if r["http_ok"])
        logger.info(f"HTTP测试完成: {success_count}/{len(http_nodes)} 成功")
        
        return results
    
    def _test_http_batch(self, batch: List[Tuple[str, Dict[str, Any], int]], batch_num: int) -> List[Dict[str, Any]]:
        """测试一批HTTP节点"""
        batch_results = []
        processes = []
        
        try:
            # 为每个节点准备配置和端口
            tasks = []
            for j, (line, node, node_id) in enumerate(batch):
                socks_port = SOCKS_PORT_START + j
                config_path = os.path.join(CONFIG_DIR, f"config_{node_id}.json")
                
                config = self.generate_singbox_config(node, socks_port)
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                
                tasks.append((line, node, node_id, socks_port, config_path))
            
            # 启动所有Sing-box实例
            for line, node, node_id, socks_port, config_path in tasks:
                process = self.run_singbox_instance(config_path, socks_port)
                if process:
                    processes.append((process, config_path))
                else:
                    batch_results.append({
                        "id": node_id, "line": line, "node": node,
                        "http_ok": False, "http_ms": -1
                    })
            
            time.sleep(2)  # 等待所有实例启动
            
            # 并行测试HTTP
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
                future_to_task = {}
                for line, node, node_id, socks_port, config_path in tasks:
                    future = executor.submit(self.http_test, socks_port)
                    future_to_task[future] = (line, node, node_id)
                
                for future in concurrent.futures.as_completed(future_to_task):
                    line, node, node_id = future_to_task[future]
                    http_ok, http_ms = future.result()
                    
                    result = {
                        "id": node_id, "line": line, "node": node,
                        "http_ok": http_ok, "http_ms": http_ms
                    }
                    batch_results.append(result)
                    
                    if http_ok:
                        logger.info(f"✅ HTTP成功: {node['server']} ({http_ms}ms)")
                    else:
                        logger.info(f"❌ HTTP失败: {node['server']}")
                        
        finally:
            # 清理进程
            for process, config_path in processes:
                self.stop_singbox_instance(process)
                try:
                    os.remove(config_path)
                except:
                    pass
        
        return batch_results
    
    def serial_download_test(self, tcp_results: List[Dict[str, Any]], 
                           http_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """串行下载测试"""
        # 收集需要测试下载的节点
        download_nodes = []
        for tcp_result in tcp_results:
            if tcp_result["tcp_ok"]:
                http_info = next((hr for hr in http_results if hr["id"] == tcp_result["id"]), None)
                if http_info:
                    download_nodes.append((
                        tcp_result["line"], tcp_result["node"], tcp_result["id"],
                        http_info.get("http_ok", False)
                    ))
        
        if not download_nodes:
            logger.warning("没有需要下载测试的节点")
            return []
        
        logger.info(f"开始下载测试 ({len(download_nodes)}个节点)...")
        results = []
        
        for i, (line, node, node_id, http_ok) in enumerate(download_nodes):
            if time.time() - self.start_time > MAX_TEST_TIME:
                logger.warning("测试超时，停止下载测试")
                break
                
            logger.info(f"下载测试进度: {i+1}/{len(download_nodes)} - {node['server']}")
            
            socks_port = SOCKS_PORT_START + i
            config_path = os.path.join(CONFIG_DIR, f"download_{node_id}.json")
            
            try:
                # 生成配置
                config = self.generate_singbox_config(node, socks_port)
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                
                # 启动Sing-box
                process = self.run_singbox_instance(config_path, socks_port)
                if not process:
                    continue
                
                try:
                    # 下载测试
                    speed, download_time = self.speed_test(socks_port)
                    
                    if download_time > 0:
                        result = {
                            "id": node_id, "line": line, "node": node,
                            "speed": speed, "download_time": download_time,
                            "http_ok": http_ok
                        }
                        results.append(result)
                        logger.info(f"✅ 下载成功: {node['server']} ({speed}Mbps, {download_time}s)")
                    else:
                        logger.info(f"❌ 下载失败: {node['server']}")
                        
                finally:
                    self.stop_singbox_instance(process)
                    try:
                        os.remove(config_path)
                    except:
                        pass
                        
            except Exception as e:
                logger.error(f"下载测试异常 {node['server']}: {e}")
        
        logger.info(f"下载测试完成: {len(results)}/{len(download_nodes)} 成功")
        return results
    
    def save_results(self, all_results: List[Dict[str, Any]]):
        """保存测试结果"""
        # 保存到ping.txt（仅节点链接）
        with open("ping.txt", "w", encoding="utf-8") as f:
            for result in all_results:
                f.write(result["line"] + "\n")
        
        # 保存详细结果
        with open("detailed_results.txt", "w", encoding="utf-8") as f:
            f.write("节点链接\tTCP延迟(ms)\tHTTP延迟(ms)\t速度(Mbps)\t下载时间(s)\t状态\n")
            for result in all_results:
                line = result["line"]
                line += f"\t{result.get('tcp_ms', -1)}"
                line += f"\t{result.get('http_ms', -1)}"
                line += f"\t{result.get('speed', 0)}"
                line += f"\t{result.get('download_time', -1)}"
                line += f"\t{'✅' if result.get('http_ok', False) else '❌'}"
                f.write(line + "\n")
    
    def run(self):
        """运行完整测试流程"""
        logger.info("🚀 开始Sing-box节点测试")
        
        # 检查Sing-box
        if not self.check_singbox():
            return
        
# 读取节点
        try:
            with open("sub.txt", "r", encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.error("❌ sub.txt 文件不存在")
            return
        except Exception as e:
            logger.error(f"❌ 读取 sub.txt 失败: {e}")
            return
        
        # 解析节点
        nodes = []
        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
                
            node = self.parse_node(line)
            if node:
                nodes.append((line, node))
                logger.info(f"✅ 解析成功 [{line_num+1}/{len(lines)}]: {node['server']}:{node['port']} ({node['type']})")
            else:
                logger.warning(f"❌ 解析失败 [{line_num+1}/{len(lines)}]: {line[:50]}...")
        
        if not nodes:
            logger.error("❌ 没有找到可用的节点")
            return
        
        logger.info(f"📋 总共解析 {len(nodes)} 个节点")
        
        # 阶段1: 批量TCP测试
        tcp_results = self.batch_tcp_test(nodes)
        tcp_success = sum(1 for r in tcp_results if r["tcp_ok"])
        logger.info(f"📊 TCP测试结果: {tcp_success}/{len(nodes)} 成功")
        
        # 阶段2: 批量HTTP测试
        http_results = self.batch_http_test(tcp_results)
        http_success = sum(1 for r in http_results if r["http_ok"])
        logger.info(f"📊 HTTP测试结果: {http_success}/{len(tcp_results)} 成功")
        
        # 阶段3: 下载测试
        download_results = self.serial_download_test(tcp_results, http_results)
        download_success = len(download_results)
        logger.info(f"📊 下载测试结果: {download_success}/{len(http_results)} 成功")
        
        # 合并结果
        all_results = []
        for download_result in download_results:
            # 查找对应的TCP和HTTP结果
            tcp_info = next((tr for tr in tcp_results if tr["id"] == download_result["id"]), {})
            http_info = next((hr for hr in http_results if hr["id"] == download_result["id"]), {})
            
            result = {
                "line": download_result["line"],
                "node": download_result["node"],
                "tcp_ms": tcp_info.get("tcp_ms", -1),
                "http_ms": http_info.get("http_ms", -1),
                "speed": download_result.get("speed", 0),
                "download_time": download_result.get("download_time", -1),
                "tcp_ok": tcp_info.get("tcp_ok", False),
                "http_ok": download_result.get("http_ok", False)
            }
            all_results.append(result)
        
        # 排序结果：按下载速度从高到低
        all_results.sort(key=lambda x: (-x["speed"], x["tcp_ms"], x["http_ms"]))
        
        # 保存结果
        self.save_results(all_results)
        
        # 统计信息
        total_time = time.time() - self.start_time
        
        # 节点类型统计
        tcp_only = sum(1 for r in all_results if r["tcp_ok"] and not r["http_ok"])
        http_only = sum(1 for r in all_results if not r["tcp_ok"] and r["http_ok"])
        both_ok = sum(1 for r in all_results if r["tcp_ok"] and r["http_ok"])
        
        # 显示结果
        logger.info("=" * 60)
        logger.info(f"🎉 测试完成！")
        logger.info(f"📊 总节点数: {len(nodes)}")
        logger.info(f"✅ 符合保留条件: {len(all_results)}")
        logger.info(f"⏱️  总耗时: {total_time:.1f}秒")
        logger.info(f"📈 平均每个节点: {total_time/max(1,len(nodes)):.1f}秒")
        
        logger.info(f"📊 节点类型统计:")
        logger.info(f"   TCP成功+HTTP成功: {both_ok}个")
        logger.info(f"   TCP成功+HTTP失败: {tcp_only}个") 
        logger.info(f"   TCP失败+HTTP成功: {http_only}个")
        
        # 显示最佳节点
        if all_results:
            best = all_results[0]
            logger.info(f"🏆 最佳节点: {best['node']['server']}")
            logger.info(f"   TCP状态: {'✅' if best['tcp_ok'] else '❌'}")
            logger.info(f"   HTTP状态: {'✅' if best['http_ok'] else '❌'}")
            if best['tcp_ok']:
                logger.info(f"   TCP延迟: {best['tcp_ms']}ms")
            if best['http_ok']:
                logger.info(f"   HTTP延迟: {best['http_ms']}ms")
            logger.info(f"   下载速度: {best['speed']}Mbps")
        
        logger.info(f"💾 结果已保存到 ping.txt 和 detailed_results.txt")
        
        # 清理临时文件
        try:
            shutil.rmtree(CONFIG_DIR, ignore_errors=True)
        except:
            pass

def main():
    """主函数"""
    tester = NodeTester()
    try:
        tester.run()
    except KeyboardInterrupt:
        logger.info("测试被用户中断")
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
    finally:
        # 确保清理临时文件
        try:
            shutil.rmtree(CONFIG_DIR, ignore_errors=True)
        except:
            pass

if __name__ == "__main__":
    main()