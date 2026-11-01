#!/usr/bin/env python3
"""
Diagnostic utility to test VeSync Cloud getConfigKeyV1 API endpoint on EU server.
Rate-limited with 1.5s delay to prevent code -16901086.
Strictly sends only the 5 fields declared in GetConfigKeyV1Request.
Pure HTTP / REST - no Bluetooth / BLE required.
"""

import argparse
import asyncio
import getpass
import json
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from pyvesync import VeSync


EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "IS", "LI", "NO", "CH", "UK", "GB"
}


async def test_endpoint(
    session: aiohttp.ClientSession,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    try:
        async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            text = await resp.text()
            try:
                data = json.loads(text)
            except Exception:
                return False, None, f"HTTP {resp.status} non-JSON: {text[:100]}"

            code = data.get("code")
            msg = data.get("msg")
            if code == 0:
                return True, data, "SUCCESS (code: 0)"
            return False, data, f"code: {code}, msg: '{msg}'"
    except Exception as e:
        return False, None, f"Network exception: {e}"


async def run_diagnostics(args: argparse.Namespace):
    email = args.email
    password = args.password
    country = (args.country or "SG").strip().upper()
    cid = args.cid or "vsaqe2ce9274f3db3a67c8a80ba70bb2"
    iv_hex = args.iv or "00112233445566778899aabbccddeeff"

    print("=" * 70)
    print("VeSync Cloud getConfigKeyV1 Diagnostic Matrix Tool (v2)")
    print("=" * 70)

    if not email:
        email = input("VeSync Email: ").strip()
    if not password:
        password = getpass.getpass("VeSync Password: ").strip()

    # Singapore / EU accounts authenticate against EU server
    api_region = "EU" if country in EU_COUNTRIES else "US"
    print(f"\n[*] Authenticating with VeSync ({api_region} server, country={country})...")

    manager = VeSync(email, password, country_code=api_region)
    try:
        login_ok = await manager.login()
    except Exception as e:
        print(f"[!] Login error: {e}")
        return

    if not login_ok:
        print("[!] Login failed. Check your credentials.")
        return

    account_id = str(manager.account_id)
    token = str(manager.token)
    user_country = getattr(manager.auth, "country_code", None) or country
    tz = getattr(manager, "time_zone", "UTC") or "UTC"
    print(f"[+] Login OK! Account ID: {account_id}, Country: {user_country}, TimeZone: {tz}")

    # Fetch Home ID
    home_id = 0
    try:
        home_resp, _ = await manager.async_call_api(
            "/cloud/v1/homeManaged/getHomeList",
            "post",
            json_object={
                "accountID": account_id,
                "token": token,
                "userCountryCode": user_country,
                "method": "getHomeList",
                "acceptLanguage": "en",
                "appVersion": "2.8.5",
                "timeZone": tz,
                "phoneBrand": "google",
                "phoneOS": "Android 14",
                "traceId": str(int(time.time() * 1000)),
            },
        )
        if home_resp and home_resp.get("code") == 0:
            res = home_resp.get("result") or {}
            hl = res.get("homeList") or []
            if hl:
                home_id = int(hl[0].get("homeId", 0))
                print(f"[+] Resolved Home ID: {home_id} ({hl[0].get('homeName')})")
    except Exception as e:
        print(f"[!] Warning fetching home list: {e}")

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
    }

    # Query EU Cloud first since user account token is valid on EU server
    servers = [
        ("https://smartapi.vesync.eu", "EU-Cloud"),
        ("https://smartapi.vesync.com", "US-Cloud"),
    ]

    models = [
        "WiFiBTOnboardingNotify_AirPurifier_Core300S_EU",
        "WiFiBTOnboardingNotify_AirPurifier_Core300S_US",
        "WiFiBTOnboardingNotify_AirPurifier_Core300S",
        "Core300S",
        "Core300S_EU",
        "LAP-C302S-WEU",
        "LAP-C301S-WAAA",
    ]

    home_options = [home_id] if home_id else []
    home_options.append(0)

    print(f"\n[*] Starting permutation testing with 1.5s rate-limit pause...")
    print(f"    Target CID: {cid}")
    print(f"    Target IV:  {iv_hex}\n")

    async with aiohttp.ClientSession() as session:
        for s_url, s_name in servers:
            url = f"{s_url}/iot/api/deviceManaged/v1/getConfigKeyV1"
            print(f"=== Testing Server: {s_name} ({s_url}) ===")
            for model in models:
                for h_val in home_options:
                    now_ms = str(int(time.time() * 1000))

                    # Strict payload matching GetConfigKeyV1Request exactly
                    payload = {
                        "context": {
                            "traceId": now_ms,
                            "method": "getConfigKeyV1",
                            "accountID": account_id,
                            "token": token,
                            "appVersion": "2.8.5",
                            "phoneOS": "Android 14",
                            "phoneBrand": "google",
                            "timeZone": tz,
                            "userCountryCode": user_country,
                            "acceptLanguage": "en",
                        },
                        "data": {
                            "configModel": model,
                            "deviceId": cid,
                            "homeId": h_val,
                            "deviceHasOrgKey": 1,
                            "randomStr": iv_hex,
                        },
                    }
                    label = f"[{s_name}] model={model} (homeId={h_val})"
                    ok, resp, status_msg = await test_endpoint(session, url, headers, payload)
                    if ok:
                        print(f"\n🎉 WINNING CONFIGURATION FOUND! 🎉")
                        print(f"Server: {s_url}")
                        print(f"Model: {model}")
                        print(f"HomeID: {h_val}")
                        print(f"Response: {resp}")
                        res = resp.get("result") or {}
                        print(f"SessionKey: {res.get('sessionKey')}")
                        print(f"ConfigKey: {res.get('configKey')}")
                        return
                    else:
                        print(f"  [-] {label} -> {status_msg}")

                    # If rate limited (-16901086), pause longer
                    if resp and resp.get("code") == -16901086:
                        print("  [!] Rate limited. Waiting 10 seconds before continuing...")
                        await asyncio.sleep(10.0)
                    else:
                        await asyncio.sleep(1.5)

    print("\n[-] All combinations tested. None returned code 0.")


def main():
    parser = argparse.ArgumentParser(description="Test VeSync getConfigKeyV1 API permutations")
    parser.add_argument("--email", "-e", help="VeSync account email")
    parser.add_argument("--password", "-p", help="VeSync account password")
    parser.add_argument("--country", "-c", default="SG", help="VeSync account country code (default: SG)")
    parser.add_argument("--cid", default="vsaqe2ce9274f3db3a67c8a80ba70bb2", help="Device CID (default: actual purifier CID)")
    parser.add_argument("--iv", default="00112233445566778899aabbccddeeff", help="16-byte K1_iv hex string (default: 32-char hex)")
    args = parser.parse_args()

    asyncio.run(run_diagnostics(args))


if __name__ == "__main__":
    main()
