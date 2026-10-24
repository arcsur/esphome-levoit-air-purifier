#!/usr/bin/env python3
"""
Levoit Core 300S Local BLE Wi-Fi Provisioning Tool (Cloud-Free)
===============================================================
Supports both:
  - Firmware v1.x (Protocol v1: RSA-1024 + AES-128-CBC via OpCode 0x8000)
  - Firmware v2.x (Protocol v2 HIGH_SECURITY_WIFI_BLE: DH + K1/K2 AES-128-CBC
    via OpCodes 0x4201, 0x4202, 0x4203, reverse-engineered from v2.0.00
    functions 0x400e8800..0x400e8c5c)

Provisions Wi-Fi credentials (OpCode 0x8012) pointing `serverDN` and `serverIP`
to a local TLS MQTT responder (`levoit_local_cloud.py`) so the ESP32 completes
its mandatory MQTT SUBACK check (`netcfg_ev_cb_nwk_connected` @ 0x400e96dc) and
persists Wi-Fi credentials to NVS flash without ever connecting to VeSync cloud.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import random
import struct
import time
from typing import Optional, Tuple

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVICE_UUID = "0000ffff-0000-1000-8000-00805f9b34fb"
CHAR_WRITE_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
CHAR_NOTIFY_UUID = "0000ff02-0000-1000-8000-00805f9b34fb"
VESYNC_COMPANY_ID = 0x06D0  # 1744

# Protocol v1 static initial AES-128-CBC credentials (from hf1/c.java & v1.1.08)
V1_DEFAULT_KEY = b"llwantaeskey1.01"
V1_DEFAULT_IV = b"llwantaesivv1.01"

# Protocol v2 reconstructed OrgKey for secretKeyVersion == 0 (from FUN_400e8800 @ 0x400e8800)
V2_DEFAULT_ORG_KEY = b"msZW1oKXw5LcyDCi8fFjXvp38HStfuqY"


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
    """
    Encodes the 6-byte VeSync transport header (FUN_400e1134 @ 0x400e1134):
      byte[0] = 0xA5
      byte[1] = 0x12 (ACK) or 0x22 (CMD)
      byte[2] = seq & 0xFF
      byte[3..4] = len(inner_payload) (LE16)
      byte[5] = checksum: 0xFF ^ (sum(header[0..4] + inner_payload) & 0xFF)
    """
    msg_type = 0x12 if is_ack else 0x22
    length = len(inner_payload)
    header_no_csum = struct.pack("<BBB H", 0xA5, msg_type, seq & 0xFF, length)
    total_sum = (sum(header_no_csum) + sum(inner_payload)) & 0xFF
    checksum = 0xFF ^ total_sum
    return header_no_csum + bytes([checksum]) + inner_payload


def make_inner_packet(
    proto_ver: int, opcode: int, key_type: int, payload: bytes
) -> bytes:
    """
    Encodes the 5-byte business header (FUN_400e80dc / FUN_400e81cc):
      byte[0] = proto_ver (1 or 2)
      byte[1..2] = opcode (LE16)
      byte[3] = 0x00 (error code / reserved)
      byte[4] = key_type (0=plain, 1=K1, 2=K2)
    """
    return struct.pack("<BHB B", proto_ver, opcode, 0x00, key_type) + payload


def derive_v2_k1(shared_secret: int, mac_no_colons_upper: str) -> Tuple[bytes, bytes]:
    """
    Derives K1_key and K1_iv from DH shared secret S and uppercase BLE MAC
    (FUN_400e8868 @ 0x400e8868 & hf1/c.java):
      K1_key = SHA256(f"{S},{MAC}")[:16]
      K1_iv  = SHA256(f"{MAC},{S}")[:16]
    """
    s1 = f"{shared_secret},{mac_no_colons_upper}".encode("ascii")
    s2 = f"{mac_no_colons_upper},{shared_secret}".encode("ascii")
    k1_key = hashlib.sha256(s1).digest()[:16]
    k1_iv = hashlib.sha256(s2).digest()[:16]
    return k1_key, k1_iv


def derive_v2_k2(
    k1_iv: bytes, cid_ascii: bytes, org_key: bytes = V2_DEFAULT_ORG_KEY
) -> bytes:
    """
    Derives K2_key from K1_iv, 32-byte CID, and 32-byte OrgKey
    (vesync_netcfg_gen_session_key @ 0x400e89e8):
      buf[0..31]  = 32 raw nibble bytes (0x00..0x0F) of K1_iv
      buf[32]     = ord(',')
      buf[33..64] = 32-byte ASCII cid
      buf[65]     = ord(',')
      buf[66..97] = 32-byte ASCII OrgKey
      K2_key      = SHA256(buf)[:16]
    """
    if len(k1_iv) != 16 or len(cid_ascii) != 32 or len(org_key) != 32:
        raise ValueError("Invalid input lengths for K2 derivation")
    nibbles = bytearray(32)
    for i, b in enumerate(k1_iv):
        nibbles[2 * i] = (b >> 4) & 0x0F
        nibbles[2 * i + 1] = b & 0x0F
    buf = bytes(nibbles) + b"," + cid_ascii + b"," + org_key
    assert len(buf) == 98
    return hashlib.sha256(buf).digest()[:16]


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def pick_dh_params() -> Tuple[int, int, int, int]:
    """
    Picks prime p in [40000, 46340], prime g in [10, 100], private a in [100, 1000],
    and public A = pow(g, a, p) (matching rd1/a0.java & FUN_400e8868).
    """
    primes_p = [x for x in range(40000, 46340) if is_prime(x)]
    primes_g = [x for x in range(10, 100) if is_prime(x)]
    p = random.choice(primes_p)
    g = random.choice(primes_g)
    a = random.randint(100, 1000)
    pub_a = pow(g, a, p)
    return p, g, a, pub_a


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
        self.ble_mac = ble_mac  # Format "AA:BB:CC:DD:EE:FF"
        self.proto_ver = 2
        self.seq = 1
        self.rx_buf = bytearray()
        self.rx_queue: asyncio.Queue = asyncio.Queue()
        self.aes_key = V1_DEFAULT_KEY
        self.aes_iv = V1_DEFAULT_IV
        self.cid: Optional[str] = None

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
        # Chunk at 180 bytes if needed
        chunk_size = 180
        for i in range(0, len(frame), chunk_size):
            await client.write_gatt_char(
                CHAR_WRITE_UUID, frame[i : i + chunk_size], response=False
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
        print(
            f"[+] Protocol v1 session key negotiated: key={self.aes_key.hex()} iv={self.aes_iv.hex()}"
        )

    async def handshake_v2(self, client: BleakClient):
        print(
            "[*] Running Protocol v2 HIGH_SECURITY_WIFI_BLE Key Exchange (0x4201 -> 0x4202 -> 0x4203)..."
        )
        if not self.ble_mac:
            raise ValueError(
                "BLE MAC address (--mac AA:BB:CC:DD:EE:FF) is required for Protocol v2 key derivation"
            )
        mac_clean = self.ble_mac.replace(":", "").replace("-", "").upper()
        mac_bytes_be = bytes.fromhex(mac_clean)
        mac_bytes_rev = mac_bytes_be[::-1]

        p, g, a, pub_a = pick_dh_params()
        now_ts = int(time.time())
        tz_offset = 0
        # 0x4201 payload: [timestamp(4B LE), tz(1B), 0x06, reversed_mac(6B), p(2B LE), g(1B), A(2B LE)]
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
        print(
            f"[+] 0x4201 DH complete (p={p}, g={g}, B={pub_b}, S={shared_s}) -> K1_key={self.aes_key.hex()}"
        )

        # 0x4202 Key Verify: send b"\x06" + reversed_ble_mac encrypted with K1 (key_type=1)
        payload_4202 = b"\x06" + dev_mac_rev
        await self.send_frame(client, 0x4202, 0x01, payload_4202, encrypt=True)
        _, _, _, _, _, _, enc_4202 = await self.wait_opcode(0x4202)
        dec_4202 = aes_cbc_decrypt(self.aes_key, self.aes_iv, enc_4202)
        if len(dec_4202) < 42 or dec_4202[0] != 0x00 or dec_4202[8] != 0x20:
            raise RuntimeError(f"0x4202 unexpected response: {dec_4202.hex()}")
        cid_rev = dec_4202[9:41]
        secret_key_ver = dec_4202[41]
        cid_bytes = cid_rev[::-1]
        self.cid = cid_bytes.decode("ascii", errors="replace")
        print(
            f"[+] 0x4202 verified! Device CID={self.cid} (secretKeyVersion={secret_key_ver})"
        )

        # Switch to K2_key while keeping K1_iv (vesync_netcfg_gen_session_key @ 0x400e89e8)
        self.aes_key = derive_v2_k2(self.aes_iv, cid_bytes, V2_DEFAULT_ORG_KEY)
        print(f"[+] Derived K2_key={self.aes_key.hex()}")

        # 0x4203 Key Update: send b"\x06" + reversed_ble_mac encrypted with K2 (key_type=2)
        await self.send_frame(client, 0x4203, 0x02, payload_4202, encrypt=True)
        _, _, _, _, _, _, enc_4203 = await self.wait_opcode(0x4203)
        dec_4203 = aes_cbc_decrypt(self.aes_key, self.aes_iv, enc_4203)
        if dec_4203[0] != 0x00:
            raise RuntimeError(f"0x4203 failed: {dec_4203.hex()}")
        print("[+] 0x4203 Key Update complete! BLE session authenticated (auth_flag=1).")

    async def provision(self, address: str):
        async with BleakClient(address) as client:
            print(f"[*] Connected to {address}")
            await client.start_notify(CHAR_NOTIFY_UUID, self._on_notify)
            await asyncio.sleep(0.5)

            if self.proto_ver == 1:
                await self.handshake_v1(client)
                key_type = 0x01
            else:
                await self.handshake_v2(client)
                key_type = 0x02

            # Build 0x8012 Wi-Fi + Local MQTT Server Config JSON
            # (parsed by vesync_netcfg_handle_cfginfo @ 0x400e8c5c & vesync_net_set_srv_info @ 0x400dfa24)
            cfg_payload = {
                "wifiSSID": self.ssid,
                "wifiPassword": self.password,
                "serverDN": f"{self.server_ip}:{self.server_port}",
                "serverIP": self.server_ip,
                "configKey": "00000000000000000000000000000000",
                "accountID": "1234567",
                "countryCode": "DE",
            }
            print(f"[*] Sending OpCode 0x8012 Wi-Fi & Local Broker config: {cfg_payload}")
            await self.send_frame(
                client,
                0x8012,
                key_type,
                json.dumps(cfg_payload, separators=(",", ":")).encode("utf-8"),
                encrypt=True,
            )

            # Wait for 0x8012 ACK and 0x8015 status updates up to CONFIG_NET_SUCCESS (step 11)
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                rem = deadline - time.monotonic()
                msg_type, seq, ver, opcode, err, kt, body = await asyncio.wait_for(
                    self.rx_queue.get(), timeout=rem
                )
                dec = aes_cbc_decrypt(self.aes_key, self.aes_iv, body) if body else b"{}"
                msg_str = dec.decode("utf-8", errors="replace")
                print(f"[<] OpCode 0x{opcode:04X} (seq={seq}): {msg_str}")
                if opcode == 0x8015:
                    # Send ACK for 0x8015 status notification
                    ack_json = json.dumps({"code": 0}, separators=(",", ":")).encode(
                        "utf-8"
                    )
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
                    if data.get("step") == 11:
                        print(
                            "[+] SUCCESS! Device reported step=11 (CONFIG_NET_SUCCESS) and saved Wi-Fi credentials to NVS!"
                        )
                        return


async def scan_and_provision(args):
    print("[*] Scanning for Levoit Core 300S in BLE pairing mode...")
    devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
    target_addr = args.address
    ble_mac = args.mac
    proto_ver = args.proto_ver

    for addr, (dev, adv) in devices.items():
        mfg = adv.manufacturer_data.get(VESYNC_COMPANY_ID)
        if mfg is not None or (dev.name and "Levoit" in dev.name):
            print(
                f"    Found {dev.name} ({addr}) mfg={mfg.hex() if mfg else 'None'}"
            )
            if target_addr is None:
                target_addr = addr
            if mfg and len(mfg) >= 12 and proto_ver is None:
                # In manufacturer data (after 2-byte company ID 0xD0 0x06),
                # byte[10] (frame byte[12]) is protocol version (1 or 2)
                proto_ver = mfg[10]
                print(f"    Detected BLE protocol version: {proto_ver}")
            if ble_mac is None and ":" in addr and len(addr) == 17:
                ble_mac = addr

    if not target_addr:
        raise RuntimeError(
            "No Levoit Core 300S found. Hold the power button for 5s until Wi-Fi LED blinks."
        )

    provisioner = LevoitBleProvisioner(
        ssid=args.ssid,
        password=args.password,
        server_ip=args.server_ip,
        server_port=args.server_port,
        ble_mac=ble_mac,
    )
    if proto_ver is not None:
        provisioner.proto_ver = proto_ver
    await provisioner.provision(target_addr)


def main():
    parser = argparse.ArgumentParser(
        description="Cloud-free BLE Wi-Fi provisioning for Levoit Core 300S"
    )
    parser.add_argument("--ssid", required=True, help="Wi-Fi SSID (2.4 GHz)")
    parser.add_argument("--password", required=True, help="Wi-Fi Password")
    parser.add_argument(
        "--server-ip",
        required=True,
        help="Local IP running levoit_local_cloud.py (e.g. 192.168.1.50)",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=1883,
        help="Local TLS MQTT port (default: 1883)",
    )
    parser.add_argument(
        "--address", help="BLE address/UUID (auto-discovered if omitted)"
    )
    parser.add_argument(
        "--mac",
        help="Device 6-byte BLE MAC (AA:BB:CC:DD:EE:FF), required on macOS for v2.0.00 where CoreBluetooth hides MACs",
    )
    parser.add_argument(
        "--proto-ver",
        type=int,
        choices=[1, 2],
        help="Force protocol version (1 for fw v1.1.x, 2 for fw v2.0.x)",
    )
    args = parser.parse_args()
    asyncio.run(scan_and_provision(args))


if __name__ == "__main__":
    main()
