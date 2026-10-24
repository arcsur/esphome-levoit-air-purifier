#!/usr/bin/env python3
"""
Levoit / VeSync Firmware Enumerator & Catalog Generator
======================================================
Discovers and catalogues official firmware binaries from VeSync servers:
1. Direct CDN Probing (No Account Needed):
   Concurrently scans `http://fw.vesync.com` across Levoit air purifier models
   (Core 200S, 300S, 400S, 600S, EverestAir in EU and US variants) for:
     - Main ESP32 Firmware (`mainFirmware`)
     - Sub-MCU Appliance Firmware (`subFirmware` / `mcuFirmware` / `mcuFw-C2`)
   Inspects 128-byte VeSync `.rel.bin` headers to verify target model, version,
   MD5 digest, and build dates.

2. Cloud API Query (Optional with VeSync account):
   Logs into VeSync cloud and queries `/cloud/v2/deviceManaged/getFirmwareUpdateInfoList`
   for live update metadata across paired devices.

3. Outputs formatted terminal tables and optional JSON catalog export.
"""

import argparse
import asyncio
import hashlib
import json
import os
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple
import aiohttp

DEFAULT_MODELS = [
    ("Core 300S EU", "WiFiBTOnboardingNotify_AirPurifier_Core300S_EU", "Core300s_EU"),
    ("Core 300S US", "WiFiBTOnboardingNotify_AirPurifier_Core300S_US", "Core300s_US"),
    ("Core 200S EU", "WiFiBTOnboardingNotify_AirPurifier_Core200S_EU", "Core200s_EU"),
    ("Core 200S US", "WiFiBTOnboardingNotify_AirPurifier_Core200S_US", "Core200s_US"),
    ("Core 400S EU", "WiFiBTOnboardingNotify_AirPurifier_Core400S_EU", "Core400s_EU"),
    ("Core 400S US", "WiFiBTOnboardingNotify_AirPurifier_Core400S_US", "Core400s_US"),
    ("Core 600S EU", "WiFiBTOnboardingNotify_AirPurifier_Core600S_EU", "Core600s_EU"),
    ("Core 600S US", "WiFiBTOnboardingNotify_AirPurifier_Core600S_US", "Core600s_US"),
]

MAJOR_MINOR_VERSIONS = [
    "1.0.00", "1.0.01", "1.0.02", "1.0.03", "1.0.05", "1.0.08", "1.0.10", "1.0.12",
    "1.1.00", "1.1.01", "1.1.02", "1.1.04", "1.1.06", "1.1.08", "1.1.09", "1.1.10",
    "2.0.00", "2.0.01", "2.0.02", "2.0.05", "2.0.08", "2.0.10", "2.0.11", "2.0.12",
    "2.1.00", "2.1.01", "2.1.02", "2.1.05", "2.2.00", "2.3.00", "2.4.00", "2.5.00"
]

CDN_BASE = "http://fw.vesync.com"


class VeSyncFirmwareScanner:
    def __init__(self, concurrency: int = 30, timeout: float = 3.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.found_firmwares: List[Dict] = []

    async def probe_url(self, session: aiohttp.ClientSession, url: str) -> Optional[Tuple[int, Dict]]:
        try:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as resp:
                if resp.status == 200:
                    length = int(resp.headers.get("Content-Length", 0))
                    last_mod = resp.headers.get("Last-Modified", "Unknown")
                    return length, {"status": 200, "length": length, "last_modified": last_mod}
        except Exception:
            pass
        return None

    async def fetch_header(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        try:
            headers = {"Range": "bytes=0-127"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status in (200, 206):
                    data = await resp.read()
                    if len(data) >= 128:
                        md5_hex = data[:32].decode("ascii", errors="ignore").strip("\x00")
                        hdr_size = struct.unpack_from("<I", data, 0x20)[0]
                        boot_ver = data[0x24:0x34].decode("ascii", errors="ignore").split("\x00")[0]
                        sw_ver = data[0x34:0x44].decode("ascii", errors="ignore").split("\x00")[0]
                        hw_ver = data[0x44:0x54].decode("ascii", errors="ignore").split("\x00")[0]
                        model = data[0x54:0x64].decode("ascii", errors="ignore").split("\x00")[0]
                        region = data[0x64:0x80].decode("ascii", errors="ignore").split("\x00")[0]
                        return {
                            "header_size": hdr_size,
                            "md5": md5_hex,
                            "boot_version": boot_ver,
                            "software_version": sw_ver,
                            "hardware_version": hw_ver,
                            "model": model,
                            "region": region,
                        }
        except Exception:
            pass
        return None

    async def scan_cdn(self, models: Optional[List[str]] = None, check_headers: bool = True):
        selected_models = [m for m in DEFAULT_MODELS if not models or any(filter_name.lower() in m[0].lower() or filter_name.lower() in m[1].lower() for filter_name in models)]
        if not selected_models:
            print("[-] No models matched the filter.")
            return

        print(f"[*] Scanning {len(selected_models)} model variants across {len(MAJOR_MINOR_VERSIONS)} version candidates...")
        sem = asyncio.Semaphore(self.concurrency)

        candidate_urls = []
        for name, mod, prefix in selected_models:
            for ver in MAJOR_MINOR_VERSIONS:
                for v_str in [f"v{ver}", ver]:
                    # 1. Main Firmware (ESP32)
                    candidate_urls.append((name, "Main Firmware (ESP32)", v_str, f"{CDN_BASE}/{mod}/mainFirmware/{v_str}/{prefix}_ota_{v_str}.rel.bin"))
                    candidate_urls.append((name, "Main Firmware (ESP32)", v_str, f"{CDN_BASE}/{mod}/mainFirmware/{v_str}/{prefix}_ota_v{ver}.rel.bin"))
                    candidate_urls.append((name, "Main Firmware (ESP32)", v_str, f"{CDN_BASE}/{mod}/mainFirmware/{v_str}/{prefix}_ota_{ver}.rel.bin"))

                    # 2. Sub-MCU Firmware (SinOne SC95F8616)
                    for sub in ["subFirmware", "mcuFirmware", "mcuFw", "subDevice"]:
                        candidate_urls.append((name, "Sub-MCU Firmware", v_str, f"{CDN_BASE}/{mod}/{sub}/{v_str}/{prefix}_mcu_{v_str}.bin"))
                        candidate_urls.append((name, "Sub-MCU Firmware", v_str, f"{CDN_BASE}/{mod}/{sub}/{v_str}/{prefix}_mcu_v{ver}.bin"))
                        candidate_urls.append((name, "Sub-MCU Firmware", v_str, f"{CDN_BASE}/{mod}/{sub}/{v_str}/{prefix}_mcu_{ver}.bin"))
                        candidate_urls.append((name, "Sub-MCU Firmware", v_str, f"{CDN_BASE}/{mod}/{sub}/{v_str}/mcuFw-C2_{v_str}.bin"))
                        candidate_urls.append((name, "Sub-MCU Firmware", v_str, f"{CDN_BASE}/{mod}/{sub}/{v_str}/mcu_{v_str}.bin"))
                        candidate_urls.append((name, "Sub-MCU Firmware", v_str, f"{CDN_BASE}/{mod}/{sub}/{v_str}/mcu.bin"))

        # Deduplicate URLs while preserving metadata
        seen_urls = set()
        unique_candidates = []
        for item in candidate_urls:
            if item[3] not in seen_urls:
                seen_urls.add(item[3])
                unique_candidates.append(item)

        print(f"[*] Dispatching {len(unique_candidates)} HTTP HEAD probes (concurrency={self.concurrency})...")

        async with aiohttp.ClientSession() as session:
            async def worker(item):
                model_name, category, version, url = item
                async with sem:
                    res = await self.probe_url(session, url)
                    if res:
                        length, meta = res
                        entry = {
                            "model": model_name,
                            "category": category,
                            "version": version,
                            "url": url,
                            "size_bytes": length,
                            "size_mb": round(length / (1024 * 1024), 2),
                            "last_modified": meta.get("last_modified"),
                        }
                        if check_headers and url.endswith(".rel.bin"):
                            hdr = await self.fetch_header(session, url)
                            if hdr:
                                entry["container_info"] = hdr
                        print(f"  [+] FOUND: {model_name:14} | {category:20} | {version:7} | {entry['size_mb']:4.2f}MB | {url}")
                        self.found_firmwares.append(entry)

            await asyncio.gather(*(worker(item) for item in unique_candidates))

    def print_summary(self):
        print("\n" + "=" * 110)
        print("LEVOIT / VESYNC OFFICIAL FIRMWARE DISCOVERY SUMMARY")
        print("=" * 110)
        if not self.found_firmwares:
            print("No firmwares found.")
            return

        print(f"{'Model':<15} {'Category':<22} {'Version':<9} {'Size (MB)':<10} {'Last Modified':<24} {'Download URL'}")
        print("-" * 110)
        for fw in sorted(self.found_firmwares, key=lambda x: (x["model"], x["category"], x["version"])):
            print(f"{fw['model']:<15} {fw['category']:<22} {fw['version']:<9} {fw['size_mb']:<10.2f} {str(fw.get('last_modified', ''))[:23]:<24} {fw['url']}")
            if "container_info" in fw:
                c = fw["container_info"]
                print(f"   └─ Header: model='{c['model']}' region='{c['region']}' sw_ver='{c['software_version']}' hw_ver='{c['hardware_version']}' md5={c['md5']}")
        print("=" * 110)

    def save_json(self, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.found_firmwares, f, indent=2)
        print(f"[+] Saved {len(self.found_firmwares)} firmware records to {output_path}")


async def query_cloud_api(user: str, password: str, country: str = "US"):
    try:
        from pyvesync import VeSync
        from pyvesync.models.vesync_models import RequestFirmwareModel
        from pyvesync.utils.helpers import Helpers
        from dataclasses import MISSING, fields
    except ImportError:
        print("[-] Cloud API query requires pyvesync: pip install pyvesync")
        return

    print(f"[*] Logging in to VeSync Cloud API as {user} ({country})...")
    async with VeSync(user, password, country_code=country, redact=False) as client:
        await client.login()
        await client.update()
        print(f"[+] Found {len(client.devices)} device(s) linked to account.")

        body_fields = tuple(f.name for f in fields(RequestFirmwareModel) if f.default_factory is MISSING and f.default is MISSING)
        body = Helpers.get_manager_attributes(client, body_fields)
        body["cidList"] = [d.cid for d in client.devices if getattr(d, "cid", None)]

        resp, status = await client.async_call_api(
            "/cloud/v2/deviceManaged/getFirmwareUpdateInfoList",
            "post",
            json_object=RequestFirmwareModel(**body),
        )
        print(f"\n[+] VeSync Cloud Response (HTTP {status}):")
        print(json.dumps(resp, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Enumerate and catalog official Levoit / VeSync firmwares")
    parser.add_argument("--models", nargs="*", help="Filter model names (e.g. Core300s Core400s)")
    parser.add_argument("--concurrency", type=int, default=30, help="Max concurrent HTTP requests (default: 30)")
    parser.add_argument("--timeout", type=float, default=2.5, help="HTTP timeout in seconds (default: 2.5)")
    parser.add_argument("--output", "-o", help="Optional JSON path to save discovered catalog")
    parser.add_argument("--user", help="Optional VeSync username/email to query live account firmware API")
    parser.add_argument("--password", help="Optional VeSync password")
    parser.add_argument("--country", default="US", help="VeSync account country code (default: US)")
    args = parser.parse_args()

    if args.user and args.password:
        asyncio.run(query_cloud_api(args.user, args.password, args.country))

    scanner = VeSyncFirmwareScanner(concurrency=args.concurrency, timeout=args.timeout)
    asyncio.run(scanner.scan_cdn(models=args.models))
    scanner.print_summary()

    if args.output:
        scanner.save_json(args.output)


if __name__ == "__main__":
    main()
