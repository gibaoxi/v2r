import asyncio
import aiohttp
import time
import sys

async def test_url_latency(session, proxy_url, target_url="https://github.com"):
    """测试代理访问URL的延迟"""
    start = time.time()
    try:
        # 设置代理
        proxy = f"http://{proxy_url}" if "://" not in proxy_url else proxy_url
        
        timeout = aiohttp.ClientTimeout(total=8)
        async with session.get(
            target_url, 
            proxy=proxy,
            timeout=timeout,
            verify_ssl=False
        ) as response:
            if response.status == 200:
                # 读取一小部分内容确认连接成功
                await response.content.read(1024)
                latency = (time.time() - start) * 1000  # 毫秒
                return (latency, proxy_url)
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        return None

async def main():
    print("开始URL延迟测试...")
    print("测试目标: https://github.com")
    
    # 读取代理链接
    try:
        with open('sub.txt', 'r', encoding='utf-8') as f:
            links = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print("错误: 找不到 sub.txt 文件")
        sys.exit(1)
    
    if not links:
        print("错误: sub.txt 中没有找到代理链接")
        sys.exit(1)
    
    print(f"找到 {len(links)} 个代理链接")
    
    # 测试所有代理
    connector = aiohttp.TCPConnector(limit=5)  # 减少并发数避免被封
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [test_url_latency(session, link) for link in links]
        print("正在测试URL访问延迟...")
        results = await asyncio.gather(*tasks)
    
    # 处理结果
    valid_results = [r for r in results if r is not None]
    valid_results.sort(key=lambda x: x[0])  # 按延迟排序
    
    print(f"可用代理: {len(valid_results)}/{len(links)}")
    
    # 写入结果
    with open('res.txt', 'w', encoding='utf-8') as f:
        for latency, link in valid_results:
            f.write(f"{link}\n")
    
    # 显示结果
    if valid_results:
        print("\nURL延迟测试结果 (从低到高):")
        for i, (latency, link) in enumerate(valid_results, 1):
            print(f"{i:2d}. {latency:6.1f}ms - {link}")
    else:
        print("没有可用的代理")

if __name__ == "__main__":
    asyncio.run(main())
