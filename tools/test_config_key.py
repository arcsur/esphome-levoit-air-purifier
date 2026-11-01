#!/usr/bin/env python3
"""
Diagnostic utility to test VeSync Cloud getConfigKeyV1 API endpoint on EU server.
Rate-limited with 1.5s delay to prevent code -16901086.
Strictly sends authentic CloudContext headers and data fields decompiled from VeSync APK.
Pure HTTP / REST - no Bluetooth / BLE required.
"""

import argparse
import asyncio
import getpass
import json
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from pyvesync import VeSync


EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "IS", "LI", "NO", "CH", "UK", "GB", "SG"
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
    country = (args.country or "EU").strip().upper()
    cid = args.cid or "vsaqe2ce9274f3db3a67c8a80ba70bb2"
    iv_hex = args.iv or "00112233445566778899aabbccddeeff"

    print("=" * 70)
    print("VeSync Cloud getConfigKeyV1 Diagnostic Matrix Tool (v3)")
    print("Authentic CloudContext & Multi-Home / Identity Verification")
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
    tz = getattr(manager, "time_zone", "America/New_York") or "America/New_York"
    print(f"[+] Login OK! Account ID: {account_id}, Country: {user_country}, TimeZone: {tz}")

    # Inspect all homes
    homes_to_test: List[Tuple[int, str, int]] = []  # (homeId, homeName, type)
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
                "appVersion": "4.4.78",
                "timeZone": tz,
                "phoneBrand": "Samsung",
                "phoneOS": "Android 14",
                "traceId": str(int(time.time() * 1000)),
            },
        )
        if home_resp and home_resp.get("code") == 0:
            res = home_resp.get("result") or {}
            hl = res.get("homeList") or []
            print(f"[*] Total homes returned: {len(hl)}")
            for h in hl:
                h_id = int(h.get("homeId", 0))
                h_name = h.get("homeName", "Unknown")
                h_type = int(h.get("type", 0))
                h_type_str = "Owner (1)" if h_type == 1 else f"Shared/Guest ({h_type})"
                print(f"    - Home ID: {h_id} | Name: '{h_name}' | Type: {h_type_str}")
                homes_to_test.append((h_id, h_name, h_type))
    except Exception as e:
        print(f"[!] Warning fetching home list: {e}")

    # If no owned home found (type == 1), create one
    has_owner_home = any(t == 1 for _, _, t in homes_to_test)
    if not has_owner_home:
        print("\n[*] No owned home found (type=1). Creating a dedicated owner home...")
        try:
            create_resp, _ = await manager.async_call_api(
                "/cloud/v1/homeManaged/updateHomeInfo",
                "post",
                json_object={
                    "accountID": account_id,
                    "token": token,
                    "userCountryCode": user_country,
                    "method": "updateHomeInfo",
                    "acceptLanguage": "en",
                    "appVersion": "4.4.78",
                    "timeZone": tz,
                    "phoneBrand": "Samsung",
                    "phoneOS": "Android 14",
                    "traceId": str(int(time.time() * 1000)),
                    "homeId": 0,
                    "homeName": "My Purifier Home",
                },
            )
            if create_resp and create_resp.get("code") == 0:
                new_hid = int(create_resp.get("result", {}).get("homeId") or 0)
                if new_hid:
                    print(f"[+] Successfully created owned Home ID: {new_hid} ('My Purifier Home')")
                    homes_to_test.insert(0, (new_hid, "My Purifier Home", 1))
            else:
                print(f"[-] Could not create home: {create_resp}")
        except Exception as e:
            print(f"[!] Exception creating home: {e}")

    terminal_id = str(uuid.uuid4()).replace("-", "")

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "VeSync/4.4.78 (SM-G998B;Android 14)",
    }

    # Authentic CloudContext as built by VeSync GlobalStoreParamProvider
    context_template = {
        "traceId": "",
        "method": "getConfigKeyV1",
        "token": token,
        "accountID": account_id,
        "timeZone": tz,
        "userCountryCode": user_country,
        "acceptLanguage": "en",
        "debugMode": False,
        "osInfo": "Android 14",
        "clientType": "vesyncApp",
        "clientVersion": "4.4.78",
        "terminalId": terminal_id,
        "clientInfo": "SM-G998B",
        "appVersion": "4.4.78",
        "phoneOS": "Android 14",
        "phoneBrand": "Samsung",
    }

    # Primary server: EU-Cloud
    servers = [
        ("https://smartapi.vesync.eu", "EU-Cloud"),
    ]

    models = [
        "WiFiBTOnboardingNotify_AirPurifier_Core300S_EU",
        "Core300S_EU",
        "Core300S",
        "LAP-C302S-WEU",
        "WiFiBTOnboardingNotify_AirPurifier_Core300S",
    ]

    device_id_variants = [
        (cid, "CID-raw"),
        (cid.upper(), "CID-uppercase"),
        ("20:9B:A9:84:C1:36", "MAC-colons"),
        ("209BA984C136", "MAC-no-colons"),
    ]

    print(f"\n[*] Starting authentic matrix test against EU-Cloud...")
    print(f"    Target CID: {cid}")
    print(f"    Target IV:  {iv_hex}")
    print(f"    Terminal ID: {terminal_id}\n")

    async with aiohttp.ClientSession() as session:
        for s_url, s_name in servers:
            url = f"{s_url}/iot/api/deviceManaged/v1/getConfigKeyV1"

            # 1. First test: Official model + each homeId + authentic context
            for h_id, h_name, h_type in homes_to_test:
                for dev_id, dev_desc in device_id_variants[:2]:  # Test CID raw and upper first
                    for org_key_val in [1, True]:
                        now_ms = str(int(time.time() * 1000))
                        ctx = dict(context_template)
                        ctx["traceId"] = now_ms

                        payload = {
                            "context": ctx,
                            "data": {
                                "configModel": "WiFiBTOnboardingNotify_AirPurifier_Core300S_EU",
                                "deviceId": dev_id,
                                "homeId": h_id,
                                "deviceHasOrgKey": org_key_val,
                                "randomStr": iv_hex,
                            },
                        }
                        label = f"model=Core300S_EU, homeId={h_id} ({h_name}), dev={dev_desc}, orgKey={org_key_val}"
                        ok, resp, status_msg = await test_endpoint(session, url, headers, payload)
                        if ok:
                            print(f"\n🎉 WINNING CONFIGURATION FOUND! 🎉")
                            print(f"Server: {s_url}")
                            print(f"Label: {label}")
                            print(f"Response: {resp}")
                            res = resp.get("result") or {}
                            print(f"SessionKey: {res.get('sessionKey')}")
                            print(f"ConfigKey: {res.get('configKey')}")
                            return
                        else:
                            print(f"  [-] {label} -> {status_msg}")

                        if resp and resp.get("code") == -16901086:
                            print("  [!] Rate limited. Waiting 10s...")
                            await asyncio.sleep(10.0)
                        else:
                            await asyncio.sleep(1.5)

            # 2. Second test: Other model candidates with best homeId
            best_home_id = homes_to_test[0][0] if homes_to_test else 0
            for model in models[1:]:
                now_ms = str(int(time.time() * 1000))
                ctx = dict(context_template)
                ctx["traceId"] = now_ms

                payload = {
                    "context": ctx,
                    "data": {
                        "configModel": model,
                        "deviceId": cid,
                        "homeId": best_home_id,
                        "deviceHasOrgKey": 1,
                        "randomStr": iv_hex,
                    },
                }
                label = f"model={model}, homeId={best_home_id}, dev=CID-raw"
                ok, resp, status_msg = await test_endpoint(session, url, headers, payload)
                if ok:
                    print(f"\n🎉 WINNING CONFIGURATION FOUND! 🎉")
                    print(f"Server: {s_url}")
                    print(f"Model: {model}")
                    print(f"Response: {resp}")
                    res = resp.get("result") or {}
                    print(f"SessionKey: {res.get('sessionKey')}")
                    print(f"ConfigKey: {res.get('configKey')}")
                    return
                else:
                    print(f"  [-] {label} -> {status_msg}")

                if resp and resp.get("code") == -16901086:
                    print("  [!] Rate limited. Waiting 10s...")
                    await asyncio.sleep(10.0)
                else:
                    await asyncio.sleep(1.5)

    print("\n[-] Matrix test finished. No configuration returned code 0.")


def main():
    parser = argparse.ArgumentParser(description="Test VeSync getConfigKeyV1 API permutations")
    parser.add_argument("--email", "-e", help="VeSync account email")
    parser.add_argument("--password", "-p", help="VeSync account password")
    parser.add_argument("--country", "-c", default="EU", help="VeSync account country code (default: EU)")
    parser.add_argument("--cid", default="vsaqe2ce9274f3db3a67c8a80ba70bb2", help="Device CID")
    parser.add_argument("--iv", default="00112233445566778899aabbccddeeff", help="16-byte K1_iv hex string")
    args = parser.parse_args()

    asyncio.run(run_diagnostics(args))


if __name__ == "__main__":
    main()
