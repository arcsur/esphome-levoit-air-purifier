#!/usr/bin/env python3
"""
Diagnostic utility to test VeSync Cloud getConfigKeyV1 API endpoint across
different regions (US vs EU), headers, payload schemas, and model SKUs.
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
    base_url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    label: str,
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    url = f"{base_url}/iot/api/deviceManaged/v1/getConfigKeyV1"
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
                return True, data, f"SUCCESS (code: 0)"
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
    print("VeSync Cloud getConfigKeyV1 Diagnostic Matrix Tool")
    print("=" * 70)

    if not email:
        email = input("VeSync Email: ").strip()
    if not password:
        password = getpass.getpass("VeSync Password: ").strip()

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

    servers = [
        ("https://smartapi.vesync.com", "US-Cloud"),
        ("https://smartapi.vesync.eu", "EU-Cloud"),
    ]

    models = [
        "WiFiBTOnboardingNotify_AirPurifier_Core300S_EU",
        "WiFiBTOnboardingNotify_AirPurifier_Core300S_US",
        "WiFiBTOnboardingNotify_AirPurifier_Core300S",
        "Core300S",
        "Core300S_EU",
        "Core300S_US",
        "LAP-C302S-WEU",
        "LAP-C301S-WAAA",
        "VS_WFON_APR_CORE300S_IN",
        "WFON_APR_LAP-C302S-WUSB_US",
    ]

    header_variants = [
        (
            "Full APK Headers",
            {
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": "VeSync/2.8.5 (Pixel 8;Android 14)",
                "Accept-Language": "en",
                "accountID": account_id,
                "tk": token,
                "tz": tz,
            },
        ),
        (
            "Basic Headers",
            {
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": "okhttp/3.12.1",
            },
        ),
    ]

    print(f"\n[*] Starting permutation testing (CID={cid}, IV={iv_hex})...\n")

    async with aiohttp.ClientSession() as session:
        for s_url, s_name in servers:
            print(f"--- Server: {s_name} ({s_url}) ---")
            for h_name, hdrs in header_variants:
                for model in models:
                    for h_val in [home_id, 0] if home_id else [0]:
                        # Permutation 1: Both configModel and configModule
                        now_ms = str(int(time.time() * 1000))
                        payload_both = {
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
                                "configModule": model,
                                "deviceId": cid,
                                "homeId": h_val,
                                "deviceHasOrgKey": 1,
                                "randomStr": iv_hex,
                            },
                        }
                        label = f"[{s_name}] [{h_name}] model={model} (homeId={h_val}, both keys)"
                        ok, resp, status_msg = await test_endpoint(session, s_url, hdrs, payload_both, label)
                        if ok:
                            print(f"\n🎉 WINNING CONFIGURATION FOUND! 🎉")
                            print(f"Server: {s_url}")
                            print(f"Headers: {h_name}")
                            print(f"Model: {model}")
                            print(f"HomeID: {h_val}")
                            print(f"Response: {resp}")
                            res = resp.get("result") or {}
                            print(f"SessionKey: {res.get('sessionKey')}")
                            print(f"ConfigKey: {res.get('configKey')}")
                            return
                        else:
                            print(f"  [-] {label} -> {status_msg}")

                        # Permutation 2: configModel only
                        payload_model_only = {
                            "context": payload_both["context"],
                            "data": {
                                "configModel": model,
                                "deviceId": cid,
                                "homeId": h_val,
                                "deviceHasOrgKey": 1,
                                "randomStr": iv_hex,
                            },
                        }
                        label2 = f"[{s_name}] [{h_name}] model={model} (homeId={h_val}, configModel only)"
                        ok2, resp2, status_msg2 = await test_endpoint(session, s_url, hdrs, payload_model_only, label2)
                        if ok2:
                            print(f"\n🎉 WINNING CONFIGURATION FOUND! 🎉")
                            print(f"Server: {s_url}")
                            print(f"Headers: {h_name}")
                            print(f"Model: {model}")
                            print(f"HomeID: {h_val}")
                            print(f"Response: {resp2}")
                            res = resp2.get("result") or {}
                            print(f"SessionKey: {res.get('sessionKey')}")
                            print(f"ConfigKey: {res.get('configKey')}")
                            return

                        # Permutation 3: Flat payload (no context/data wrapping)
                        payload_flat = {
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
                            "configModel": model,
                            "configModule": model,
                            "deviceId": cid,
                            "homeId": h_val,
                            "deviceHasOrgKey": 1,
                            "randomStr": iv_hex,
                        }
                        label3 = f"[{s_name}] [{h_name}] model={model} (homeId={h_val}, flat body)"
                        ok3, resp3, status_msg3 = await test_endpoint(session, s_url, hdrs, payload_flat, label3)
                        if ok3:
                            print(f"\n🎉 WINNING CONFIGURATION FOUND! 🎉")
                            print(f"Server: {s_url}")
                            print(f"Headers: {h_name}")
                            print(f"Model: {model}")
                            print(f"Payload: Flat")
                            print(f"Response: {resp3}")
                            res = resp3.get("result") or {}
                            print(f"SessionKey: {res.get('sessionKey')}")
                            print(f"ConfigKey: {res.get('configKey')}")
                            return

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
