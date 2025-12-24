
import asyncio
import aiohttp
import time

class ProxySpeedTester:
    def __init__(self):
        self.test_url = "https://github.com"
        self.timeout = 10
    
    def load_proxy_links(self):
        """从sub.txt加载代理链接"""
        try:
            with open('sub.txt', 'r', encoding='utf-8') as f:
                links = [line.strip() for line in f if line.strip()]
            print(f"加载了 {len(links)} 个代理链接")
            return links
        except:
            return []
    
    async def test_single_proxy(self, session, link):
        """测试单个代理的速度"""
        start_time = time.time()
        try:
            async with session.get(self.test_url, timeout=self.timeout) as response:
                if response.status == 200:
                    speed = len(await response.read()) / (time.time() - start_time)
                    return {
                        'link': link,
                        'speed': speed / 125000,  # 转换为 Mbps
                        'latency': (time.time() - start_time) * 1000
                    }
        except:
            return None
    
    async def test_all_proxies(self, links):
        """测试所有代理"""
        results = []
        async with aiohttp.ClientSession() as session:
            tasks = [self.test_single_proxy(session, link) for link in links]
            results = await asyncio.gather(*tasks)
        
        # 过滤掉失败的测试
        valid_results = [r for r in results if r]
        print(f"测试完成，可用: {len(valid_results)}/{len(links)}")
        return valid_results
    
    def save_results(self, results):
        """保存结果到res.txt"""
        # 按速度排序
        results.sort(key=lambda x: x['speed'], reverse=True)
        
        with open('res.txt', 'w', encoding='utf-8') as f:
            for i, result in enumerate(results, 1):
                f.write(f"{result['speed']:.2f}Mbps {result['latency']:.0f}ms {result['link']}\n")

async def main():
    tester = ProxySpeedTester()
    links = tester.load_proxy_links()
    
    if links:
        results = await tester.test_all_proxies(links)
        tester.save_results(results)
        print("结果已保存到 res.txt")

if __name__ == "__main__":
    asyncio.run(main())
