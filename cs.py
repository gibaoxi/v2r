import asyncio
import aiohttp
import time
import sys

async def test_proxy(session, link):
    """测试单个代理的延迟"""
    start = time.time()
    try:
        timeout = aiohttp.ClientTimeout(total=5)  # 5秒超时
        async with session.get("https://github.com", timeout=timeout) as r:
            if r.status == 200:
                # 只读取前100字节，不下载完整内容
                await r.content.read(100)
                latency = (time.time() - start) * 1000
                return (latency, link)
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        return None

async def main():
    print("开始代理延迟测试...")
    
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
    connector = aiohttp.TCPConnector(limit=10)  # 限制并发数
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [test_proxy(session, link) for link in links]
        print("正在测试延迟...")
        results = await asyncio.gather(*tasks)
    
    # 处理结果
    valid_results = [r for r in results if r is not None]
    valid_results.sort(key=lambda x: x[0])  # 按延迟排序
    
    print(f"可用代理: {len(valid_results)}/{len(links)}")
    
    # 写入结果
    with open('res.txt', 'w', encoding='utf-8') as f:
        for latency, link in valid_results:
            f.write(link + "\n")
    
    # 显示最快的前5个
    if valid_results:
        print("\n最快的前5个代理:")
        for i, (latency, link) in enumerate(valid_results[:5], 1):
            print(f"{i}. {latency:.0f}ms - {link[:80]}...")

if __name__ == "__main__":
    asyncio.run(main())
