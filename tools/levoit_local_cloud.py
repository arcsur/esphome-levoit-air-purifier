#!/usr/bin/env python3
"""
Levoit Core 300S Local TLS MQTT Responder & HTTP OTA Server
===========================================================
1. Completes the Core 300S's mandatory post-BLE MQTT TLS handshake on port 1883
   (CONNECT -> CONNACK, SUBSCRIBE `mqtt/<cid>/v2/rsp` & `mqtt/<cid>/v2/bypass`
   -> SUBACK) so `netcfg_ev_cb_nwk_connected` (0x400e96dc) commits the Wi-Fi
   credentials to NVS flash without ever touching the VeSync cloud.
2. Optionally triggers a local OTA update (`bypassV2` -> `upFirmware`) over MQTT
   and serves the firmware image over HTTP on port 18080:
   - `--plugin mainFw`   : Updates the ESP32-SOLO-1 (stock `.rel.bin` or an
                           ESPHome binary wrapped with `--wrap-esphome`).
   - `--plugin mcuFw-C2` : Updates the SinOne SC95F8616 Main Controller MCU
                           over UART (`vesync_ota_sub_device_upgrade` @ 0x400dcf10).
3. Includes `--wrap-esphome <in.bin> <out.rel.bin>` to build a valid 128-byte
   VeSync `.rel.bin` OTA container verified by `main_dev_fw_dl_cb` (0x400dc864).
"""

import argparse
import asyncio
import datetime
import hashlib
import json
import os
import socket
import ssl
import struct
import tempfile
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def get_default_local_ip() -> str:
    """
    Auto-detects the host's primary local LAN IPv4 address
    by probing routing to an external address without sending packets.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"



def wrap_vesync_ota_header(
    input_bin_path: str,
    output_rel_path: str,
    sw_ver: str = "2.0.00",
    hw_ver: str = "1.0",
    boot_ver: str = "1.0",
    model: str = "Core300s",
    region: str = "EU",
) -> None:
    """
    Constructs the 128-byte VeSync `.rel.bin` header validated by
    `main_dev_fw_dl_cb` (0x400dc864) and `FUN_400dc4e0` (0x400dc4e0):
      [0x00..0x1F] : 32-byte lowercase ASCII MD5 hex of the payload after offset 0x80
      [0x20..0x23] : LE32 header size = 0x00000080 (128)
      [0x24..0x33] : Bootloader version string (e.g. "1.0")
      [0x34..0x43] : Software version string (e.g. "2.0.00") - must match `newVersion`!
      [0x44..0x53] : Hardware version string (e.g. "1.0")
      [0x54..0x63] : Model name string (e.g. "Core300s")
      [0x64..0x7F] : Region string (e.g. "EU")
    """
    with open(input_bin_path, "rb") as f:
        payload = f.read()

    # If the user passed a full factory image (with bootloader at 0x1000 and app at 0x10000),
    # warn if byte[0] != 0xE9 or if it looks like a merged flash image.
    if len(payload) > 0x10000 and payload[0x10000] == 0xE9 and payload[0] != 0xE9:
        print(
            "[*] Detected merged ESPHome factory image; slicing application partition at offset 0x10000..."
        )
        payload = payload[0x10000:]

    md5_hex = hashlib.md5(payload).hexdigest().lower().encode("ascii")
    header = bytearray(128)
    header[0x00:0x20] = md5_hex

    def put_str(offset: int, max_len: int, val: str):
        raw = val.encode("ascii")[: max_len - 1]
        header[offset : offset + len(raw)] = raw

    struct.pack_into("<I", header, 0x20, 0x80)
    put_str(0x24, 16, boot_ver)
    put_str(0x34, 16, sw_ver)
    put_str(0x44, 16, hw_ver)
    put_str(0x54, 16, model)
    put_str(0x64, 28, region)

    with open(output_rel_path, "wb") as f:
        f.write(header)
        f.write(payload)

    print(
        f"[+] Wrote wrapped VeSync OTA image to {output_rel_path} "
        f"(payload={len(payload)} bytes, MD5={md5_hex.decode()}, sw_ver={sw_ver})"
    )


def generate_self_signed_ssl_ctx() -> ssl.SSLContext:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "vesync.local")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".pem") as cf, \
         tempfile.NamedTemporaryFile("wb", delete=False, suffix=".key") as kf:
        cf.write(cert_pem)
        kf.write(key_pem)
        cert_path, key_path = cf.name, kf.name

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    os.unlink(cert_path)
    os.unlink(key_path)
    return ctx


def encode_mqtt_varlen(length: int) -> bytes:
    out = bytearray()
    while True:
        encoded = length % 128
        length //= 128
        if length > 0:
            encoded |= 0x80
        out.append(encoded)
        if length == 0:
            break
    return bytes(out)


async def read_mqtt_packet(reader: asyncio.StreamReader):
    first = await reader.readexactly(1)
    pkt_type = first[0]
    multiplier = 1
    rem_len = 0
    while True:
        b = (await reader.readexactly(1))[0]
        rem_len += (b & 127) * multiplier
        multiplier *= 128
        if (b & 128) == 0:
            break
    payload = await reader.readexactly(rem_len) if rem_len > 0 else b""
    return pkt_type, payload


def build_mqtt_publish(topic: str, payload: bytes) -> bytes:
    topic_bytes = topic.encode("utf-8")
    body = struct.pack(">H", len(topic_bytes)) + topic_bytes + payload
    return bytes([0x30]) + encode_mqtt_varlen(len(body)) + body


class LocalVeSyncBroker:
    def __init__(
        self,
        server_ip: str,
        http_port: int,
        ota_file: str = None,
        plugin_name: str = "mainFw",
        new_version: str = "2.0.00",
    ):
        self.server_ip = server_ip
        self.http_port = http_port
        self.ota_file = ota_file
        self.plugin_name = plugin_name
        self.new_version = new_version
        self.ota_sent = False

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        peer = writer.get_extra_info("peername")
        print(f"[+] TLS MQTT connection established from {peer}")
        cid = None
        sub_count = 0
        try:
            while True:
                pkt_type, body = await read_mqtt_packet(reader)
                high_nibble = pkt_type >> 4

                if high_nibble == 1:  # CONNECT
                    print("[<] MQTT CONNECT received -> sending CONNACK")
                    writer.write(b"\x20\x02\x00\x00")
                    await writer.drain()

                elif high_nibble == 8:  # SUBSCRIBE
                    pkt_id = struct.unpack_from(">H", body, 0)[0]
                    idx = 2
                    return_codes = bytearray()
                    while idx < len(body):
                        tlen = struct.unpack_from(">H", body, idx)[0]
                        idx += 2
                        topic = body[idx : idx + tlen].decode("utf-8", errors="replace")
                        idx += tlen
                        _qos = body[idx]
                        idx += 1
                        return_codes.append(0x00)
                        sub_count += 1
                        print(f"[<] MQTT SUBSCRIBE topic='{topic}' (sub #{sub_count})")
                        parts = topic.split("/")
                        if len(parts) >= 2 and parts[0] == "mqtt":
                            cid = parts[1]

                    suback_body = struct.pack(">H", pkt_id) + bytes(return_codes)
                    writer.write(
                        b"\x90" + encode_mqtt_varlen(len(suback_body)) + suback_body
                    )
                    await writer.drain()

                    # Once both `mqtt/<cid>/v2/rsp` and `mqtt/<cid>/v2/bypass` are subscribed,
                    # `FUN_400dee3c` posts event 0x0C and the Core 300S commits Wi-Fi to NVS!
                    if sub_count >= 2:
                        print(
                            f"[+] Both MQTT SUBACKs sent for CID={cid}! "
                            "Device has now committed Wi-Fi credentials to NVS flash."
                        )
                        if self.ota_file and cid and not self.ota_sent:
                            self.ota_sent = True
                            await asyncio.sleep(2.0)
                            await self.send_ota_command(writer, cid)

                elif high_nibble == 3:  # PUBLISH
                    tlen = struct.unpack_from(">H", body, 0)[0]
                    topic = body[2 : 2 + tlen].decode("utf-8", errors="replace")
                    offset = 2 + tlen
                    if (pkt_type & 0x06) != 0:
                        pkt_id = struct.unpack_from(">H", body, offset)[0]
                        offset += 2
                        writer.write(b"\x40\x02" + struct.pack(">H", pkt_id))
                        await writer.drain()
                    msg = body[offset:].decode("utf-8", errors="replace")
                    print(f"[<] MQTT PUBLISH on '{topic}': {msg}")

                elif high_nibble == 12:  # PINGREQ
                    writer.write(b"\xD0\x00")
                    await writer.drain()

                elif high_nibble == 14:  # DISCONNECT
                    print("[*] Device sent MQTT DISCONNECT")
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError):
            print(f"[*] MQTT connection closed by {peer}")
        finally:
            writer.close()

    async def send_ota_command(self, writer: asyncio.StreamWriter, cid: str):
        ota_url = f"http://{self.server_ip}:{self.http_port}/fw.bin"
        cmd = {
            "traceId": str(int(datetime.datetime.now().timestamp())),
            "method": "bypassV2",
            "debugMode": False,
            "payload": {
                "method": "upFirmware",
                "source": "Cloud",
                "data": {
                    "newVersion": self.new_version,
                    "pluginName": self.plugin_name,
                    "urlV1": ota_url,
                    "upMode": 2,
                },
            },
        }
        topic = f"mqtt/{cid}/v2/bypass"
        payload_bytes = json.dumps(cmd, separators=(",", ":")).encode("utf-8")
        print(
            f"[>] Publishing OTA trigger to '{topic}': pluginName={self.plugin_name}, "
            f"newVersion={self.new_version}, urlV1={ota_url}"
        )
        writer.write(build_mqtt_publish(topic, payload_bytes))
        await writer.drain()


async def run_servers(args):
    broker = LocalVeSyncBroker(
        server_ip=args.server_ip,
        http_port=args.http_port,
        ota_file=args.ota_file,
        plugin_name=args.plugin,
        new_version=args.new_version,
    )
    ssl_ctx = generate_self_signed_ssl_ctx()
    mqtt_server = await asyncio.start_server(
        broker.handle_client, host="0.0.0.0", port=args.mqtt_port, ssl=ssl_ctx
    )
    print(f"[*] Local TLS MQTT broker listening on 0.0.0.0:{args.mqtt_port}")

    if args.ota_file:
        app = web.Application()

        async def serve_fw(_request):
            print(f"[>] Serving OTA binary '{args.ota_file}' over HTTP...")
            return web.FileResponse(path=args.ota_file)

        app.router.add_get("/fw.bin", serve_fw)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", args.http_port)
        await site.start()
        print(
            f"[*] Local HTTP OTA server listening on http://{args.server_ip}:{args.http_port}/fw.bin"
        )

    async with mqtt_server:
        await mqtt_server.serve_forever()


def main():
    parser = argparse.ArgumentParser(
        description="Local TLS MQTT Responder & OTA Server for Levoit Core 300S"
    )
    parser.add_argument(
        "--wrap-esphome",
        nargs=2,
        metavar=("IN_BIN", "OUT_REL_BIN"),
        help="Wrap an ESPHome .bin with the 128-byte VeSync .rel.bin OTA header and exit",
    )
    parser.add_argument(
        "--server-ip",
        default=None,
        help="This machine's LAN IPv4 address (default: auto-detected host IP)",
    )
    parser.add_argument(
        "--mqtt-port", type=int, default=1883, help="TLS MQTT port (default: 1883)"
    )
    parser.add_argument(
        "--http-port", type=int, default=18080, help="HTTP OTA port (default: 18080)"
    )
    parser.add_argument(
        "--ota-file",
        help="Optional firmware binary to push via `upFirmware` once device connects",
    )
    parser.add_argument(
        "--plugin",
        default="mainFw",
        choices=["mainFw", "mcuFw-C2"],
        help="Target controller: 'mainFw' (ESP32) or 'mcuFw-C2' (SC95F8616 Main MCU)",
    )
    parser.add_argument(
        "--new-version",
        default="2.0.00",
        help="Firmware version string reported in `upFirmware` (must match header sw_ver for mainFw)",
    )
    args = parser.parse_args()

    if args.wrap_esphome:
        wrap_vesync_ota_header(
            args.wrap_esphome[0], args.wrap_esphome[1], sw_ver=args.new_version
        )
        return

    if not args.server_ip:
        args.server_ip = get_default_local_ip()
        print(f"[*] Auto-detected local server IP: {args.server_ip}")

    asyncio.run(run_servers(args))


if __name__ == "__main__":
    main()
