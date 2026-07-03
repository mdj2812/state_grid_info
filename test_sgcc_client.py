#!/usr/bin/env python3
"""Test SGCC API client — standalone login + data fetch.

Usage:
    # Set credentials in env
    export SGCC_USERNAME="your_phone"
    export SGCC_PASSWORD="your_password"

    # Test login only
    python3 test_sgcc_client.py --login

    # Test full data fetch
    python3 test_sgcc_client.py
"""

import asyncio
import json
import logging
import os
import sys

# Ensure we can import sgcc_api
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sgcc_api import SgccClient, SgccError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
)


async def test_login() -> None:
    """Test login + list households."""
    username = os.environ.get("SGCC_USERNAME", "")
    password = os.environ.get("SGCC_PASSWORD", "")

    if not username or not password:
        print("ERROR: Set SGCC_USERNAME and SGCC_PASSWORD environment variables")
        sys.exit(1)

    async with SgccClient(debug=True) as client:
        try:
            households = await client.login(username, password)
            print(f"\n✅ 登录成功！共 {len(households)} 个户号:\n")
            for u in households:
                print(f"  户号: {u.get('consNo_dst', '?')}")
                print(f"  户名: {u.get('consName_dst', u.get('consName', ''))}")
                print(f"  地址: {u.get('elecAddr_dst', u.get('elecAddr', ''))}")
                print(f"  供电单位: {u.get('orgName', '')}")
                print()
        except SgccError as e:
            print(f"\n❌ 登录失败: {e}")
            sys.exit(1)


async def test_fetch() -> None:
    """Login + fetch all data."""
    username = os.environ.get("SGCC_USERNAME", "")
    password = os.environ.get("SGCC_PASSWORD", "")

    if not username or not password:
        print("ERROR: Set SGCC_USERNAME and SGCC_PASSWORD environment variables")
        sys.exit(1)

    async with SgccClient(debug=True) as client:
        try:
            await client.login(username, password)
            results = await client.fetch_all()

            print(f"\n{'='*60}")
            print(f"✅ 数据拉取完成！共 {len(results)} 户")
            print(f"{'='*60}")

            for r in results:
                d = r["data"]
                print(f"\n{'─'*50}")
                print(f"户号: {r['consNo']}")
                print(f"户名: {r['consName']}")
                print(f"地址: {r['address']}")
                print(f"供电单位: {r['orgName']}")
                print(f"\n💰 余额: {d['sumMoney']} 元")
                print(f"⚡ 本年累计: {d['totalEleNum']} kWh")
                print(f"💵 本年电费: {d['totalEleCost']} 元")
                print(f"\n📅 日数据 ({len(d['dayList'])} 条):")
                for item in d["dayList"][-5:]:
                    print(f"  {item['day']} | {item.get('dayElePq', 0)} kWh")
                print(f"\n📊 月数据 ({len(d['monthList'])} 条):")
                for item in d["monthList"][-5:]:
                    print(f"  {item['month']} | {item.get('monthEleNum', 0)} kWh | ¥{item.get('monthEleCost', 0)}")

            print(f"\n{'='*60}")
            print("完整 JSON:")
            print(json.dumps(results, ensure_ascii=False, indent=2))

        except SgccError as e:
            print(f"\n❌ 失败: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    if "--login" in sys.argv:
        asyncio.run(test_login())
    else:
        asyncio.run(test_fetch())
