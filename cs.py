import asyncio
import aiohttp
import time

async def test_proxy(session, link):
    start = time.time()
    try:
        async with session.get("https://github.com", timeout=10) as r:
            if r.status == 200:
                await r.read()
                latency = (time.time() - start) * 1000  # 延迟(毫秒)
                return (latency, link)
    except:
        return None

async def main():
    with open('sub.txt', 'r') as f:
        links = [l.strip() for l in f if l.strip()]
    
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[test_proxy(session, link) for link in links])
    
    # 过滤掉失败的，按延迟排序
    valid_results = [r for r in results if r]
    valid_results.sort(key=lambda x: x[0])  # 按延迟从小到大排序
    
    with open('res.txt', 'w') as f:
        for latency, link in valid_results:
            f.write(link + "\n")

asyncio.run(main())
