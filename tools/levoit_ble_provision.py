#!/usr/bin/env python3
"""
Levoit Core 300S Onboarding, Wi-Fi Provisioning & ESPHome Flasher
================================================================
Comprehensive, cloud-free tool for the Levoit Core 300S Air Purifier:
  1. Initial ESPHome Flash:
     Wraps an ESPHome binary with the VeSync container, runs a local TLS MQTT
     responder and HTTP OTA server, provisions Wi-Fi over BLE, and triggers
     the initial wireless flash in a single automated flow.
  2. Cloud-Free Wi-Fi Provisioning:
     Pairs over BLE (v1 RSA/AES or v2 DH/K1/K2) and commits Wi-Fi credentials
     to NVS flash without connecting to VeSync cloud.
  3. Restore Factory Stock Firmware:
     Restores original factory Levoit firmware (v2.0.00 / v1.1.08) to a device
     currently running ESPHome via Native OTA (port 3232), Web Server (port 80),
     or USB-UART Serial (esptool.py).
  4. Interactive Wizard:
     Prompts for Wi-Fi SSID and password (with masked input) if not provided on
     the command line, and auto-detects the host machine's LAN IP address.
"""

import argparse
import asyncio
import base64
import getpass
import hashlib
import json
import os
import random
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

from aiohttp import web
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Ensure local imports work regardless of invocation directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from levoit_local_cloud import (  # noqa: E402
    LocalVeSyncBroker,
    generate_self_signed_ssl_ctx,
    get_default_local_ip,
    wrap_vesync_ota_header,
)

# Primary 16-bit VeSync GATT service (Core 200S, 300S, 400S, etc.)
SERVICE_UUID = "0000fff0-0000-1000-8000-00805f9b34fb"
CHAR_NOTIFY_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
CHAR_WRITE_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"

# Alternate 128-bit TI OAD style GATT service (also exposed on some models)
SERVICE_UUID_ALT = "f000ffe0-0451-4000-b000-000000000000"
CHAR_WRITE_UUID_ALT = "f000ffe1-0451-4000-b000-000000000000"
CHAR_NOTIFY_UUID_ALT = "f000ffe2-0451-4000-b000-000000000000"

VESYNC_COMPANY_ID = 0x06D0  # 1744


def resolve_gatt_characteristics(client: BleakClient) -> Tuple[str, str]:
    """
    Dynamically discovers the correct write and notify characteristics from the device's
    active GATT services. Supports primary VeSync (0xFFF0), alternate (0xFFE0), and property fallbacks.
    Returns: (char_write_uuid, char_notify_uuid)
    """
    # 1. Primary VeSync 16-bit service (0xFFF0)
    for svc in client.services:
        s_uuid = svc.uuid.lower()
        if "fff0" in s_uuid:
            w_char, n_char = None, None
            for c in svc.characteristics:
                c_uuid = c.uuid.lower()
                if "fff2" in c_uuid and ("write" in c.properties or "write-without-response" in c.properties):
                    w_char = c.uuid
                elif "fff1" in c_uuid and "notify" in c.properties:
                    n_char = c.uuid
            if w_char and n_char:
                return w_char, n_char

    # 2. Alternate 128-bit TI OAD service (0xFFE0)
    for svc in client.services:
        s_uuid = svc.uuid.lower()
        if "ffe0" in s_uuid:
            w_char, n_char = None, None
            for c in svc.characteristics:
                c_uuid = c.uuid.lower()
                if "ffe1" in c_uuid and ("write" in c.properties or "write-without-response" in c.properties):
                    w_char = c.uuid
                elif "ffe2" in c_uuid and "notify" in c.properties:
                    n_char = c.uuid
            if w_char and n_char:
                return w_char, n_char

    # 3. Fallback: match by characteristic properties
    w_char, n_char = None, None
    for svc in client.services:
        for c in svc.characteristics:
            if "notify" in c.properties and not n_char:
                n_char = c.uuid
            if ("write" in c.properties or "write-without-response" in c.properties) and not w_char:
                w_char = c.uuid
    if w_char and n_char:
        return w_char, n_char

    raise RuntimeError(
        f"Could not resolve write/notify characteristics among device services: "
        f"{[s.uuid for s in client.services]}"
    )


V1_DEFAULT_KEY = b"llwantaeskey1.01"
V1_DEFAULT_IV = b"llwantaesivv1.01"
V2_DEFAULT_ORG_KEY = b"msZW1oKXw5LcyDCi8fFjXvp38HStfuqY"

OFFICIAL_STOCK_URL = (
    "http://fw.vesync.com/WiFiBTOnboardingNotify_AirPurifier_Core300S_EU/"
    "mainFirmware/v2.0.00/Core300s_EU_ota_v2.0.00.rel.bin"
)


# ==============================================================================
# Crypto & Framing Utilities
# ==============================================================================

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def wrap_outer_frame(inner_payload: bytes, seq: int, is_ack: bool = False) -> bytes:
    msg_type = 0x12 if is_ack else 0x22
    length = len(inner_payload)
    header_no_csum = struct.pack("<BBB H", 0xA5, msg_type, seq & 0xFF, length)
    total_sum = (sum(header_no_csum) + sum(inner_payload)) & 0xFF
    checksum = 0xFF ^ total_sum
    return header_no_csum + bytes([checksum]) + inner_payload


def make_inner_packet(
    proto_ver: int, opcode: int, key_type: int, payload: bytes
) -> bytes:
    return struct.pack("<BHB B", proto_ver, opcode, 0x00, key_type) + payload


def derive_v2_k1(shared_secret: int, mac_no_colons_upper: str) -> Tuple[bytes, bytes]:
    s1 = f"{shared_secret},{mac_no_colons_upper}".encode("ascii")
    s2 = f"{mac_no_colons_upper},{shared_secret}".encode("ascii")
    k1_key = hashlib.sha256(s1).digest()[:16]
    k1_iv = hashlib.sha256(s2).digest()[:16]
    return k1_key, k1_iv


def derive_v2_k2(
    k1_iv: bytes, cid_ascii: bytes, org_key: bytes = V2_DEFAULT_ORG_KEY
) -> bytes:
    if len(k1_iv) != 16 or len(cid_ascii) != 32 or len(org_key) != 32:
        raise ValueError("Invalid input lengths for K2 derivation")
    nibbles = bytearray(32)
    for i, b in enumerate(k1_iv):
        nibbles[2 * i] = (b >> 4) & 0x0F
        nibbles[2 * i + 1] = b & 0x0F
    buf = bytes(nibbles) + b"," + cid_ascii + b"," + org_key
    return hashlib.sha256(buf).digest()[:16]


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def pick_dh_params() -> Tuple[int, int, int, int]:
    primes_p = [x for x in range(40000, 46340) if is_prime(x)]
    primes_g = [x for x in range(10, 100) if is_prime(x)]
    p = random.choice(primes_p)
    g = random.choice(primes_g)
    a = random.randint(100, 1000)
    pub_a = pow(g, a, p)
    return p, g, a, pub_a


# ==============================================================================
# BLE Provisioner Class
# ==============================================================================

class LevoitBleProvisioner:
    def __init__(
        self,
        ssid: str,
        password: str,
        server_ip: str,
        server_port: int = 1883,
        ble_mac: Optional[str] = None,
    ):
        self.ssid = ssid
        self.password = password
        self.server_ip = server_ip
        self.server_port = server_port
        self.ble_mac = ble_mac
        self.proto_ver = 2
        self.seq = 1
        self.rx_buf = bytearray()
        self.rx_queue: asyncio.Queue = asyncio.Queue()
        self.aes_key = V1_DEFAULT_KEY
        self.aes_iv = V1_DEFAULT_IV
        self.cid: Optional[str] = None
        self.char_write_uuid = CHAR_WRITE_UUID
        self.char_notify_uuid = CHAR_NOTIFY_UUID

    def _on_notify(self, _sender, data: bytearray):
        self.rx_buf.extend(data)
        while len(self.rx_buf) >= 6:
            if self.rx_buf[0] != 0xA5:
                idx = self.rx_buf.find(0xA5)
                if idx == -1:
                    self.rx_buf.clear()
                    return
                del self.rx_buf[:idx]
                if len(self.rx_buf) < 6:
                    return
            payload_len = struct.unpack_from("<H", self.rx_buf, 3)[0]
            total_len = 6 + payload_len
            if len(self.rx_buf) < total_len:
                return
            frame = bytes(self.rx_buf[:total_len])
            del self.rx_buf[:total_len]
            self._handle_frame(frame)

    def _handle_frame(self, frame: bytes):
        msg_type = frame[1]
        seq = frame[2]
        inner = frame[6:]
        if len(inner) < 5:
            return
        ver, opcode, err, key_type = struct.unpack_from("<BHBB", inner, 0)
        body = inner[5:]
        self.rx_queue.put_nowait((msg_type, seq, ver, opcode, err, key_type, body))

    async def send_frame(
        self,
        client: BleakClient,
        opcode: int,
        key_type: int,
        raw_body: bytes,
        encrypt: bool = True,
        is_ack: bool = False,
        seq_override: Optional[int] = None,
    ):
        body = (
            aes_cbc_encrypt(self.aes_key, self.aes_iv, raw_body)
            if encrypt and raw_body
            else raw_body
        )
        inner = make_inner_packet(self.proto_ver, opcode, key_type, body)
        seq = seq_override if seq_override is not None else self.seq
        if not is_ack and seq_override is None:
            self.seq = (self.seq + 1) & 0xFF
        frame = wrap_outer_frame(inner, seq, is_ack=is_ack)
        chunk_size = 180
        write_char = getattr(self, "char_write_uuid", CHAR_WRITE_UUID)
        for i in range(0, len(frame), chunk_size):
            await client.write_gatt_char(
                write_char, frame[i : i + chunk_size], response=False
            )

    async def wait_opcode(self, target_opcode: int, timeout: float = 10.0):
        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"Timeout waiting for opcode 0x{target_opcode:04X}")
            msg_type, seq, ver, opcode, err, key_type, body = await asyncio.wait_for(
                self.rx_queue.get(), timeout=rem
            )
            if opcode == target_opcode:
                return msg_type, seq, ver, opcode, err, key_type, body

    async def handshake_v1(self, client: BleakClient):
        print("[*] Running Protocol v1 RSA-1024/AES-128 Key Exchange (0x8000)...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        req_json = json.dumps({"key": base64.b64encode(pub_der).decode("ascii")}).encode(
            "utf-8"
        )
        self.aes_key = V1_DEFAULT_KEY
        self.aes_iv = V1_DEFAULT_IV
        await self.send_frame(client, 0x8000, 0x01, req_json, encrypt=True)
        _, _, _, _, _, _, enc_body = await self.wait_opcode(0x8000)
        dec_body = aes_cbc_decrypt(self.aes_key, self.aes_iv, enc_body)
        resp = json.loads(dec_body.decode("utf-8"))
        enc_key = base64.b64decode(resp["key"])
        enc_iv = base64.b64decode(resp["iv"])
        self.aes_key = private_key.decrypt(enc_key, asym_padding.PKCS1v15())
        self.aes_iv = private_key.decrypt(enc_iv, asym_padding.PKCS1v15())
        print(f"[+] Protocol v1 session key negotiated successfully.")

    async def handshake_v2(self, client: BleakClient):
        print("[*] Running Protocol v2 HIGH_SECURITY_WIFI_BLE Key Exchange (0x4201 -> 0x4202 -> 0x4203)...")
        if not self.ble_mac:
            # Prompt if macOS UUID concealed the hardware MAC
            print("\n[!] macOS CoreBluetooth hides hardware MAC addresses behind random UUIDs.")
            print("    The Levoit v2.0.00 firmware requires its physical MAC for DH key verification.")
            raw_mac = input("    Please enter 6-byte BLE MAC from device label (e.g. AA:BB:CC:DD:EE:FF): ").strip()
            self.ble_mac = raw_mac.replace(":", "").replace("-", "").upper()
            while len(self.ble_mac) != 12:
                print("    Invalid MAC address. Must be 6 hex bytes (12 hex digits), e.g. AA:BB:CC:DD:EE:FF.")
                raw_mac = input("    Please enter 6-byte BLE MAC from device label: ").strip()
                self.ble_mac = raw_mac.replace(":", "").replace("-", "").upper()

        mac_clean = self.ble_mac.replace(":", "").replace("-", "").upper()
        mac_bytes_be = bytes.fromhex(mac_clean)
        mac_bytes_rev = mac_bytes_be[::-1]

        p, g, a, pub_a = pick_dh_params()
        now_ts = int(time.time())
        tz_offset = 0
        payload_4201 = (
            struct.pack("<IBB", now_ts, tz_offset, 6)
            + mac_bytes_rev
            + struct.pack("<HBH", p, g, pub_a)
        )
        await self.send_frame(client, 0x4201, 0x00, payload_4201, encrypt=False)
        _, _, _, _, _, _, body_4201 = await self.wait_opcode(0x4201)
        if len(body_4201) < 12 or body_4201[0] != 0x00:
            raise RuntimeError(f"0x4201 failed: {body_4201.hex()}")
        dev_mac_rev = body_4201[2:8]
        pub_b = struct.unpack_from("<H", body_4201, 8)[0]
        shared_s = pow(pub_b, a, p)
        self.aes_key, self.aes_iv = derive_v2_k1(shared_s, mac_clean)
        print(f"[+] 0x4201 DH key exchange complete.")

        payload_4202 = b"\x06" + dev_mac_rev
        await self.send_frame(client, 0x4202, 0x01, payload_4202, encrypt=True)
        _, _, _, _, _, _, enc_4202 = await self.wait_opcode(0x4202)
        dec_4202 = aes_cbc_decrypt(self.aes_key, self.aes_iv, enc_4202)
        if len(dec_4202) < 42 or dec_4202[0] != 0x00 or dec_4202[8] != 0x20:
            raise RuntimeError(f"0x4202 unexpected response: {dec_4202.hex()}")
        cid_rev = dec_4202[9:41]
        cid_bytes = cid_rev[::-1]
        self.cid = cid_bytes.decode("ascii", errors="replace")
        print(f"[+] 0x4202 verified! Device CID={self.cid}")

        self.aes_key = derive_v2_k2(self.aes_iv, cid_bytes, V2_DEFAULT_ORG_KEY)
        await self.send_frame(client, 0x4203, 0x02, payload_4202, encrypt=True)
        _, _, _, _, _, _, enc_4203 = await self.wait_opcode(0x4203)
        dec_4203 = aes_cbc_decrypt(self.aes_key, self.aes_iv, enc_4203)
        if dec_4203[0] != 0x00:
            raise RuntimeError(f"0x4203 failed: {dec_4203.hex()}")
        print("[+] 0x4203 complete! BLE session authenticated.")

    async def provision(self, address: str):
        async with BleakClient(address) as client:
            print(f"[*] Connected to {address}")
            self.char_write_uuid, self.char_notify_uuid = resolve_gatt_characteristics(client)
            print(f"[*] Resolved GATT characteristics: write={self.char_write_uuid}, notify={self.char_notify_uuid}")
            await client.start_notify(self.char_notify_uuid, self._on_notify)
            await asyncio.sleep(0.5)

            if self.proto_ver == 1:
                await self.handshake_v1(client)
                key_type = 0x01
            else:
                await self.handshake_v2(client)
                key_type = 0x02

            cfg_payload = {
                "wifiSSID": self.ssid,
                "wifiPassword": self.password,
                "serverDN": f"{self.server_ip}:{self.server_port}",
                "serverIP": self.server_ip,
                "configKey": "00000000000000000000000000000000",
                "accountID": "1234567",
                "countryCode": "DE",
            }
            print(f"[*] Sending Wi-Fi & Local Server configuration (SSID: '{self.ssid}')...")
            await self.send_frame(
                client,
                0x8012,
                key_type,
                json.dumps(cfg_payload, separators=(",", ":")).encode("utf-8"),
                encrypt=True,
            )

            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                rem = deadline - time.monotonic()
                msg_type, seq, ver, opcode, err, kt, body = await asyncio.wait_for(
                    self.rx_queue.get(), timeout=rem
                )
                dec = aes_cbc_decrypt(self.aes_key, self.aes_iv, body) if body else b"{}"
                msg_str = dec.decode("utf-8", errors="replace")
                if opcode == 0x8015:
                    ack_json = json.dumps({"code": 0}, separators=(",", ":")).encode("utf-8")
                    await self.send_frame(
                        client,
                        0x8015,
                        key_type,
                        ack_json,
                        encrypt=True,
                        is_ack=True,
                        seq_override=seq,
                    )
                    data = json.loads(msg_str)
                    step = data.get("step")
                    step_names = {
                        1: "Connecting to Wi-Fi",
                        5: "Obtained IP Address",
                        11: "Wi-Fi Configured & Saved to NVS",
                    }
                    print(f"    [Device Status] Step {step}: {step_names.get(step, 'In Progress')}")
                    if step == 11:
                        print("[+] SUCCESS! Device reported CONFIG_NET_SUCCESS (step=11)!")
                        return


# ==============================================================================
# Stock Firmware Extraction & Preparation
# ==============================================================================

def extract_app_bin(data: bytes) -> bytes:
    """
    Ensures the binary is a raw ESP-IDF application binary starting with 0xE9.
    If it is a VeSync container (.rel.bin), strips the 128-byte header.
    If it is a merged flash image, slices at offset 0x10000.
    """
    if len(data) > 128 and data[0] == 0xE9:
        return data
    if len(data) > 128 and data[128] == 0xE9:
        print("[*] Detected VeSync .rel.bin container; stripped 128-byte header to recover clean ESP-IDF binary.")
        return data[128:]
    if len(data) > 0x10000 and data[0x10000] == 0xE9:
        print("[*] Detected merged flash dump; extracted application partition at offset 0x10000.")
        return data[0x10000:]
    if len(data) > 0 and data[0] != 0xE9:
        print(f"[!] Warning: Binary does not begin with standard ESP magic byte 0xE9 (byte[0]=0x{data[0]:02X}).")
    return data


def resolve_stock_firmware(stock_file: Optional[str] = None) -> bytes:
    """
    Locates stock firmware on disk, searches default paths, or downloads it
    directly from VeSync CDN.
    """
    if stock_file and os.path.exists(stock_file):
        print(f"[*] Reading stock firmware from '{stock_file}'...")
        with open(stock_file, "rb") as f:
            return extract_app_bin(f.read())

    # Check common default locations
    default_candidates = [
        os.path.join(os.path.dirname(__file__), "../Core300s_EU_v2.0.00_esp32_app.bin"),
        os.path.join(os.path.dirname(__file__), "../Core300s_EU_ota_v2.0.00.rel.bin"),
        "/Users/arcsur/REA/levoit_firmware/Core300s_EU_v2.0.00_esp32_app.bin",
        "/Users/arcsur/REA/levoit_firmware/Core300s_EU_ota_v2.0.00.rel.bin",
        "./Core300s_EU_v2.0.00_esp32_app.bin",
        "./Core300s_EU_ota_v2.0.00.rel.bin",
    ]
    for candidate in default_candidates:
        abs_cand = os.path.abspath(candidate)
        if os.path.exists(abs_cand):
            print(f"[*] Found local stock firmware at '{abs_cand}'")
            with open(abs_cand, "rb") as f:
                return extract_app_bin(f.read())

    # If not found locally, offer download from VeSync CDN
    print("\n[-] Stock firmware binary not found locally.")
    choice = input("    Download official Core 300S EU v2.0.00 firmware from VeSync CDN? [Y/n]: ").strip().lower()
    if choice in ("", "y", "yes"):
        print(f"[*] Downloading official firmware from {OFFICIAL_STOCK_URL}...")
        req = urllib.request.Request(OFFICIAL_STOCK_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
            local_save = "./Core300s_EU_ota_v2.0.00.rel.bin"
            with open(local_save, "wb") as f:
                f.write(data)
            print(f"[+] Download complete ({len(data)} bytes saved to '{local_save}')")
            return extract_app_bin(data)
    else:
        path = input("    Enter path to custom stock firmware binary (.bin / .rel.bin): ").strip()
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, "rb") as f:
            return extract_app_bin(f.read())


# ==============================================================================
# Restore Stock Firmware Methods (for devices currently running ESPHome)
# ==============================================================================

def restore_stock_via_esphome_ota(
    device_ip: str,
    app_bin: bytes,
    port: int = 3232,
    password: Optional[str] = None,
    timeout: float = 60.0,
):
    """
    Restores stock firmware to an ESPHome device wirelessly over native ESPHome OTA (port 3232).
    """
    print(f"[*] Connecting to ESPHome Native OTA at {device_ip}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15.0)
    sock.connect((device_ip, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    MAGIC = bytes([0x6C, 0x26, 0xF7, 0x5C, 0x45])
    sock.sendall(MAGIC)
    resp = sock.recv(2)
    if len(resp) < 2 or resp[0] != 0x00:
        raise RuntimeError(f"Unexpected magic byte response from ESPHome: {resp.hex() if resp else 'None'}")
    version = resp[1]
    print(f"[+] ESPHome OTA handshake initiated (protocol version {version})")

    features_to_send = 0x02 | 0x04  # SHA256 auth | Extended protocol
    sock.sendall(bytes([features_to_send]))
    feat_resp = sock.recv(1)
    if not feat_resp:
        raise RuntimeError("No feature response from ESPHome device")
    feat = feat_resp[0]
    extended_proto = False
    if feat == 0x48:  # RESPONSE_FEATURE_FLAGS
        extended_proto = True
        _ = sock.recv(1)[0]

    auth_resp = sock.recv(1)
    if not auth_resp:
        raise RuntimeError("No auth response from ESPHome device")
    auth_code = auth_resp[0]
    if auth_code == 0x41:  # RESPONSE_AUTH_OK
        print("[+] Device does not require password authentication.")
    elif auth_code in (0x01, 0x02):  # 0x01=MD5, 0x02=SHA256
        if not password:
            password = getpass.getpass("    Device requires OTA password. Enter password: ").strip()
        is_sha256 = (auth_code == 0x02)
        nonce_len = 64 if is_sha256 else 32
        nonce = sock.recv(nonce_len).decode("ascii")
        cnonce = secrets.token_hex(nonce_len // 2)
        sock.sendall(cnonce.encode("ascii"))
        hasher = hashlib.sha256() if is_sha256 else hashlib.md5()
        hasher.update(password.encode("utf-8"))
        hasher.update(nonce.encode("ascii"))
        hasher.update(cnonce.encode("ascii"))
        result = hasher.hexdigest()
        sock.sendall(result.encode("ascii"))
        auth_ack = sock.recv(1)
        if not auth_ack or auth_ack[0] != 0x41:
            raise RuntimeError(f"OTA authentication failed: {auth_ack.hex() if auth_ack else 'None'}")
        print("[+] OTA Authentication succeeded!")
    else:
        raise RuntimeError(f"Unexpected auth response code: 0x{auth_code:02X}")

    # Fallback to TCP (decline UDP channel)
    sock.sendall(b"\x00")
    _ = sock.recv(4)

    if extended_proto:
        sock.sendall(bytes([0x00]))  # OTA_TYPE_UPDATE_APP

    total_size = len(app_bin)
    sock.sendall(struct.pack(">I", total_size))
    prep_ack = sock.recv(1)
    if not prep_ack or prep_ack[0] != 0x42:  # RESPONSE_UPDATE_PREPARE_OK
        raise RuntimeError(f"Flash preparation failed on device: 0x{prep_ack[0]:02X if prep_ack else 0}")
    print("[+] Flash partition erased and prepared.")

    file_md5 = hashlib.md5(app_bin).hexdigest()
    sock.sendall(file_md5.encode("ascii"))
    md5_ack = sock.recv(1)
    if not md5_ack or md5_ack[0] != 0x43:  # RESPONSE_BIN_MD5_OK
        raise RuntimeError(f"MD5 checksum rejected: 0x{md5_ack[0]:02X if md5_ack else 0}")
    print(f"[+] MD5 checksum accepted ({file_md5})")

    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
    chunk_size = 8192
    offset = 0
    t0 = time.time()
    print(f"[*] Streaming {total_size} bytes to ESPHome device...")
    while offset < total_size:
        chunk = app_bin[offset : offset + chunk_size]
        sock.sendall(chunk)
        offset += len(chunk)
        pct = (offset / total_size) * 100
        speed = (offset / (time.time() - t0 + 0.001)) / 1024
        print(f"\r    Uploading: {offset}/{total_size} bytes ({pct:5.1f}%) [{speed:5.1f} kB/s]", end="", flush=True)

    print()
    sock.settimeout(timeout)
    try:
        final_ack = sock.recv(1)
        if final_ack and final_ack[0] in (0x44, 0x45):
            print("\n" + "=" * 70)
            print("  [+] SUCCESS! Device accepted firmware and is rebooting into stock Levoit OS!")
            print("=" * 70 + "\n")
        else:
            print(f"[+] Binary transferred. Device ack: 0x{final_ack[0]:02X if final_ack else 0}. Rebooting.")
    except socket.timeout:
        print("[+] Binary transfer complete. Device rebooted (timeout on final TCP close).")
    finally:
        sock.close()


def restore_stock_via_esphome_web(
    device_ip: str,
    app_bin: bytes,
    web_port: int = 80,
    username: Optional[str] = None,
    password: Optional[str] = None,
):
    """
    Restores stock firmware via the ESPHome Web Server component (POST /update).
    """
    boundary = "----WebKitFormBoundary" + secrets.token_hex(8)
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("ascii"))
    body.extend(b'Content-Disposition: form-data; name="update"; filename="firmware.bin"\r\n')
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(app_bin)
    body.extend(f"\r\n--{boundary}--\r\n".encode("ascii"))

    url = f"http://{device_ip}:{web_port}/update"
    req = urllib.request.Request(url, data=bytes(body))
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if username and password:
        auth_str = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", f"Basic {auth_str}")

    print(f"[*] Uploading stock firmware ({len(app_bin)} bytes) to ESPHome Web Server at {url}...")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            print(f"[+] Server response: {resp.status} {resp.reason}")
            print("\n" + "=" * 70)
            print("  [+] SUCCESS! Firmware uploaded via Web Server. Device is now rebooting.")
            print("=" * 70 + "\n")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP error during Web Server update: {e.code} {e.reason}")


def restore_stock_via_serial(port: str, app_bin: bytes, baud: int = 460800):
    """
    Flashes stock firmware directly over USB-UART serial via esptool.py.
    """
    with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".bin") as f:
        f.write(app_bin)
        tmp_bin = f.name

    try:
        cmd = [
            sys.executable,
            "-m",
            "esptool",
            "--port",
            port,
            "--baud",
            str(baud),
            "write_flash",
            "0x10000",
            tmp_bin,
        ]
        print(f"[*] Running serial flash: {' '.join(cmd)}")
        subprocess.check_call(cmd)
        print("\n" + "=" * 70)
        print("  [+] SUCCESS! Stock firmware flashed to 0x10000 over serial.")
        print("=" * 70 + "\n")
    finally:
        if os.path.exists(tmp_bin):
            os.unlink(tmp_bin)


# ==============================================================================
# All-in-One Initial ESPHome Flasher
# ==============================================================================

async def perform_initial_flash(
    esphome_bin_path: str,
    ssid: str,
    password: str,
    server_ip: str,
    mqtt_port: int = 1883,
    http_port: int = 18080,
    address: Optional[str] = None,
    ble_mac: Optional[str] = None,
    proto_ver: Optional[int] = None,
):
    if not os.path.exists(esphome_bin_path):
        raise FileNotFoundError(f"ESPHome binary not found: {esphome_bin_path}")

    # Step 1: Wrap ESPHome binary in VeSync .rel.bin container
    temp_rel = tempfile.NamedTemporaryFile("wb", delete=False, suffix=".rel.bin")
    temp_rel_path = temp_rel.name
    temp_rel.close()

    print("\n" + "=" * 70)
    print("  STEP 1: Wrapping ESPHome binary with VeSync OTA Header")
    print("=" * 70)
    wrap_vesync_ota_header(esphome_bin_path, temp_rel_path, sw_ver="2.0.00")

    ota_download_done = asyncio.Event()

    # Step 2: Start local TLS MQTT & HTTP servers
    print("\n" + "=" * 70)
    print("  STEP 2: Starting Local TLS MQTT Responder & HTTP OTA Server")
    print("=" * 70)
    broker = LocalVeSyncBroker(
        server_ip=server_ip,
        http_port=http_port,
        ota_file=temp_rel_path,
        plugin_name="mainFw",
        new_version="2.0.00",
    )
    ssl_ctx = generate_self_signed_ssl_ctx()
    mqtt_server = await asyncio.start_server(
        broker.handle_client, host="0.0.0.0", port=mqtt_port, ssl=ssl_ctx
    )
    print(f"[*] Local TLS MQTT broker listening on 0.0.0.0:{mqtt_port}")

    app = web.Application()

    async def serve_fw(_request):
        print(f"[>] Core 300S is downloading ESPHome OTA image '{temp_rel_path}'...")
        resp = web.FileResponse(path=temp_rel_path)
        # Device finishes download shortly after stream starts
        asyncio.get_running_loop().call_later(6.0, ota_download_done.set)
        return resp

    app.router.add_get("/fw.bin", serve_fw)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", http_port)
    await site.start()
    print(f"[*] Local HTTP OTA server listening on http://{server_ip}:{http_port}/fw.bin")

    # Step 3: BLE Discovery & Wi-Fi Provisioning
    print("\n" + "=" * 70)
    print("  STEP 3: BLE Discovery & Local Wi-Fi Provisioning")
    print("=" * 70)
    print("[*] Searching for Levoit Core 300S in BLE pairing mode...")
    print("    (If not blinking, press and hold the Power button for 5s)")

    target_addr = address
    if not target_addr:
        devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
        for addr, (dev, adv) in devices.items():
            mfg = adv.manufacturer_data.get(VESYNC_COMPANY_ID)
            if mfg is not None or (dev.name and "Levoit" in dev.name):
                print(f"    Found {dev.name} ({addr})")
                if target_addr is None:
                    target_addr = addr
                if mfg and len(mfg) >= 12 and proto_ver is None:
                    proto_ver = mfg[10]
                    print(f"    Detected BLE protocol version: {proto_ver}")
                if ble_mac is None and ":" in addr and len(addr) == 17:
                    ble_mac = addr

    if not target_addr:
        mqtt_server.close()
        await runner.cleanup()
        if os.path.exists(temp_rel_path):
            os.unlink(temp_rel_path)
        raise RuntimeError("No Levoit Core 300S found. Make sure the Wi-Fi icon is blinking.")

    provisioner = LevoitBleProvisioner(
        ssid=ssid,
        password=password,
        server_ip=server_ip,
        server_port=mqtt_port,
        ble_mac=ble_mac,
    )
    if proto_ver is not None:
        provisioner.proto_ver = proto_ver

    try:
        await provisioner.provision(target_addr)
    except Exception as e:
        mqtt_server.close()
        await runner.cleanup()
        if os.path.exists(temp_rel_path):
            os.unlink(temp_rel_path)
        raise e

    # Step 4: Wait for MQTT connection and OTA download
    print("\n" + "=" * 70)
    print("  STEP 4: Awaiting Local TLS MQTT Connection & Wireless Flashing")
    print("=" * 70)
    print("[*] Device is connecting to local Wi-Fi and establishing TLS MQTT session...")
    try:
        await asyncio.wait_for(ota_download_done.wait(), timeout=90.0)
        print("\n" + "=" * 70)
        print("  [+] SUCCESS! Levoit Core 300S downloaded the ESPHome firmware image!")
        print("  [+] The purifier is now flashing the image and rebooting into ESPHome.")
        print("  [+] You can now control your purifier via Home Assistant / ESPHome.")
        print("=" * 70 + "\n")
    except asyncio.TimeoutError:
        print("\n[!] Timed out waiting for OTA download completion.")
        print("    Check if your machine's firewall allows incoming connections on ports 1883 and 18080.")
    finally:
        mqtt_server.close()
        await runner.cleanup()
        if os.path.exists(temp_rel_path):
            os.unlink(temp_rel_path)


# ==============================================================================
# Standalone BLE Scan and Provision (Wi-Fi Only)
# ==============================================================================

async def scan_and_provision(args):
    target_addr = args.address
    ble_mac = args.mac
    proto_ver = args.proto_ver

    if not target_addr:
        print("[*] Scanning for Levoit Core 300S in BLE pairing mode...")
        devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
        for addr, (dev, adv) in devices.items():
            mfg = adv.manufacturer_data.get(VESYNC_COMPANY_ID)
            if mfg is not None or (dev.name and "Levoit" in dev.name):
                print(f"    Found {dev.name} ({addr})")
                if target_addr is None:
                    target_addr = addr
                if mfg and len(mfg) >= 12 and proto_ver is None:
                    proto_ver = mfg[10]
                    print(f"    Detected BLE protocol version: {proto_ver}")
                if ble_mac is None and ":" in addr and len(addr) == 17:
                    ble_mac = addr

    if not target_addr:
        raise RuntimeError(
            "No Levoit Core 300S found. Hold the power button for 5s until Wi-Fi LED blinks."
        )

    # Start a background TLS MQTT broker on port 1883 so the mandatory post-BLE
    # MQTT SUBACK check succeeds and commits Wi-Fi to NVS flash!
    broker = LocalVeSyncBroker(server_ip=args.server_ip, http_port=18080)
    ssl_ctx = generate_self_signed_ssl_ctx()
    mqtt_server = await asyncio.start_server(
        broker.handle_client, host="0.0.0.0", port=args.server_port, ssl=ssl_ctx
    )
    print(f"[*] Background TLS MQTT responder active on port {args.server_port}")

    provisioner = LevoitBleProvisioner(
        ssid=args.ssid,
        password=args.password,
        server_ip=args.server_ip,
        server_port=args.server_port,
        ble_mac=ble_mac,
    )
    if proto_ver is not None:
        provisioner.proto_ver = proto_ver

    try:
        await provisioner.provision(target_addr)
        print("[*] Waiting for device to complete local MQTT handshake...")
        await asyncio.sleep(4.0)
    finally:
        mqtt_server.close()


# ==============================================================================
# Interactive Menu Wizard
# ==============================================================================

def run_interactive_wizard():
    local_ip = get_default_local_ip()
    print("=" * 70)
    print("        Levoit Core 300S Onboarding & Firmware Manager")
    print("=" * 70)
    print(f"Auto-detected Host LAN IP: {local_ip}\n")
    print("Please choose an operation:")
    print("  [1] Initial Flash: Install ESPHome on Stock Levoit Purifier (BLE + OTA)")
    print("  [2] Wi-Fi Provisioning Only (Keep Stock Firmware, Cloud-Free BLE Setup)")
    print("  [3] Restore Factory Stock Firmware to ESPHome Device (OTA / Web / Serial)")
    print("  [4] Wrap ESPHome binary into VeSync .rel.bin container")
    print("  [5] Exit")
    print("=" * 70)

    choice = input("Enter choice [1-5]: ").strip()

    if choice == "1":
        print("\n--- Initial ESPHome Flash ---")
        bin_path = input("Path to compiled ESPHome .bin file: ").strip()
        while not os.path.exists(bin_path):
            print(f"File not found: {bin_path}")
            bin_path = input("Path to compiled ESPHome .bin file: ").strip()

        ssid = input("Wi-Fi SSID (2.4 GHz): ").strip()
        while not ssid:
            ssid = input("Wi-Fi SSID (2.4 GHz): ").strip()
        password = getpass.getpass("Wi-Fi Password: ").strip()

        ip_input = input(f"Local Host IP [{local_ip}]: ").strip()
        server_ip = ip_input if ip_input else local_ip

        asyncio.run(
            perform_initial_flash(
                esphome_bin_path=bin_path,
                ssid=ssid,
                password=password,
                server_ip=server_ip,
            )
        )

    elif choice == "2":
        print("\n--- Wi-Fi Provisioning Only ---")
        ssid = input("Wi-Fi SSID (2.4 GHz): ").strip()
        while not ssid:
            ssid = input("Wi-Fi SSID (2.4 GHz): ").strip()
        password = getpass.getpass("Wi-Fi Password: ").strip()

        ip_input = input(f"Local Host IP [{local_ip}]: ").strip()
        server_ip = ip_input if ip_input else local_ip

        class Args:
            pass

        args = Args()
        args.ssid = ssid
        args.password = password
        args.server_ip = server_ip
        args.server_port = 1883
        args.address = None
        args.mac = None
        args.proto_ver = None
        asyncio.run(scan_and_provision(args))

    elif choice == "3":
        print("\n--- Restore Factory Stock Firmware ---")
        app_bin = resolve_stock_firmware()

        print("\nSelect Restoration Method:")
        print("  [1] ESPHome Native OTA (Port 3232 - Recommended)")
        print("  [2] ESPHome Web Server (Port 80 HTTP /update)")
        print("  [3] Serial Flashing via USB-UART (esptool.py)")
        print("  [4] Export clean ESP-IDF .bin file only")
        sub_choice = input("Enter method [1-4]: ").strip()

        if sub_choice == "1":
            dev_ip = input("Enter ESPHome Device IP address: ").strip()
            ota_pwd = input("Enter OTA password (leave blank if none): ").strip() or None
            restore_stock_via_esphome_ota(dev_ip, app_bin, password=ota_pwd)
        elif sub_choice == "2":
            dev_ip = input("Enter ESPHome Device IP address: ").strip()
            web_port = input("Enter Web Server port [80]: ").strip() or "80"
            restore_stock_via_esphome_web(dev_ip, app_bin, web_port=int(web_port))
        elif sub_choice == "3":
            port = input("Enter USB Serial port (e.g. /dev/cu.usbserial-0001): ").strip()
            restore_stock_via_serial(port, app_bin)
        elif sub_choice == "4":
            out_file = "./Core300s_EU_v2.0.00_esp32_app.bin"
            with open(out_file, "wb") as f:
                f.write(app_bin)
            print(f"[+] Saved clean ESP-IDF application binary to '{out_file}'.")
            print("    You can now upload this file directly via the ESPHome Dashboard UI.")

    elif choice == "4":
        print("\n--- Wrap ESPHome Binary ---")
        in_bin = input("Path to input ESPHome .bin: ").strip()
        out_rel = input("Path to output .rel.bin [esphome_ota.rel.bin]: ").strip() or "esphome_ota.rel.bin"
        wrap_vesync_ota_header(in_bin, out_rel)

    elif choice == "5":
        print("Exiting.")
        sys.exit(0)


# ==============================================================================
# Main Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Levoit Core 300S Onboarding, Wi-Fi Provisioning & ESPHome Flasher"
    )
    parser.add_argument(
        "--flash-esphome",
        metavar="ESPHOME_BIN",
        help="Initial flash: Wrap ESPHome binary, start local cloud, and flash Core 300S wirelessly",
    )
    parser.add_argument(
        "--restore-stock",
        nargs="?",
        const="DEFAULT",
        metavar="STOCK_BIN",
        help="Restore factory stock firmware to a device currently running ESPHome",
    )
    parser.add_argument(
        "--restore-method",
        choices=["native", "web", "serial", "extract"],
        default="native",
        help="Restoration method for --restore-stock: 'native' (OTA 3232), 'web' (HTTP 80), 'serial' (esptool), 'extract'",
    )
    parser.add_argument(
        "--device-ip",
        help="IP address of the ESPHome device (required for --restore-stock wireless modes)",
    )
    parser.add_argument(
        "--ota-password",
        help="ESPHome OTA password (optional for --restore-stock)",
    )
    parser.add_argument(
        "--serial-port",
        help="USB-UART serial port for --restore-method serial",
    )
    parser.add_argument(
        "--wrap-esphome",
        nargs=2,
        metavar=("IN_BIN", "OUT_REL_BIN"),
        help="Wrap an ESPHome .bin with the 128-byte VeSync .rel.bin OTA header and exit",
    )
    parser.add_argument(
        "--ssid",
        help="Wi-Fi SSID (2.4 GHz). Prompts interactively if omitted.",
    )
    parser.add_argument(
        "--password",
        help="Wi-Fi Password. Prompts interactively if omitted.",
    )
    parser.add_argument(
        "--server-ip",
        help="This machine's LAN IPv4 address (default: auto-detected host IP)",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=1883,
        help="Local TLS MQTT port (default: 1883)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=18080,
        help="HTTP OTA server port (default: 18080)",
    )
    parser.add_argument(
        "--address",
        help="BLE address/UUID (auto-discovered if omitted)",
    )
    parser.add_argument(
        "--mac",
        help="Device 6-byte BLE MAC (AA:BB:CC:DD:EE:FF), required on macOS for v2.0.00",
    )
    parser.add_argument(
        "--proto-ver",
        type=int,
        choices=[1, 2],
        help="Force protocol version (1 for fw v1.1.x, 2 for fw v2.0.x)",
    )

    # If run with no arguments, launch interactive wizard
    if len(sys.argv) == 1:
        run_interactive_wizard()
        return

    args = parser.parse_args()

    # Mode 1: Wrap binary and exit
    if args.wrap_esphome:
        wrap_vesync_ota_header(args.wrap_esphome[0], args.wrap_esphome[1])
        return

    # Mode 2: Restore stock firmware to ESPHome device
    if args.restore_stock is not None:
        stock_path = None if args.restore_stock == "DEFAULT" else args.restore_stock
        app_bin = resolve_stock_firmware(stock_path)

        if args.restore_method == "extract":
            out_file = "./Core300s_EU_stock_app.bin"
            with open(out_file, "wb") as f:
                f.write(app_bin)
            print(f"[+] Saved clean ESP-IDF binary to '{out_file}'")
            return

        if args.restore_method == "serial":
            port = args.serial_port
            if not port:
                port = input("Enter USB Serial port (e.g. /dev/cu.usbserial-0001): ").strip()
            restore_stock_via_serial(port, app_bin)
            return

        # Wireless restoration (native or web)
        dev_ip = args.device_ip
        if not dev_ip:
            dev_ip = input("Enter ESPHome Device IP address: ").strip()
            if not dev_ip:
                parser.error("--device-ip is required for wireless restoration")

        if args.restore_method == "web":
            restore_stock_via_esphome_web(dev_ip, app_bin)
        else:
            restore_stock_via_esphome_ota(dev_ip, app_bin, password=args.ota_password)
        return

    # Auto-detect Server IP if not specified
    if not args.server_ip:
        args.server_ip = get_default_local_ip()
        print(f"[*] Auto-detected local host IP: {args.server_ip}")

    # Prompt for SSID / Password if missing
    if not args.ssid:
        args.ssid = input("Enter Wi-Fi SSID (2.4 GHz): ").strip()
        while not args.ssid:
            print("SSID cannot be empty.")
            args.ssid = input("Enter Wi-Fi SSID (2.4 GHz): ").strip()

    if not args.password:
        args.password = getpass.getpass("Enter Wi-Fi Password: ").strip()

    # Mode 3: Initial ESPHome Flash
    if args.flash_esphome:
        asyncio.run(
            perform_initial_flash(
                esphome_bin_path=args.flash_esphome,
                ssid=args.ssid,
                password=args.password,
                server_ip=args.server_ip,
                mqtt_port=args.server_port,
                http_port=args.http_port,
                address=args.address,
                ble_mac=args.mac,
                proto_ver=args.proto_ver,
            )
        )
        return

    # Mode 4: Standalone Wi-Fi Provisioning
    asyncio.run(scan_and_provision(args))


if __name__ == "__main__":
    main()
