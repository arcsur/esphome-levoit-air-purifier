# Levoit Air Purifier Local Pairing & OTA Tooling

This directory contains standalone Python tools to configure and wirelessly update Levoit Air Purifiers (such as the Core 300S EU 240V model) **completely without a VeSync cloud account**.

## Tools

### 1. `levoit_ble_provision.py`
Pairs with the purifier over Bluetooth Low Energy (BLE) and configures Wi-Fi credentials:
* Supports both **Protocol v1** (AES-128 / RSA-1024) and **Protocol v2** (`HIGH_SECURITY_WIFI_BLE` Diffie-Hellman + dynamic $K_1$/$K_2$ session key generation used in firmware `v2.0.00`).
* Redirects the device's mandatory onboarding MQTT connection to a local TLS MQTT server (`levoit_local_cloud.py`) so the device persists credentials to NVS flash without an internet connection.

#### Usage:
```bash
python3 levoit_ble_provision.py \
    --ssid "YourWiFiSSID" \
    --password "YourWiFiPassword" \
    --server-ip 192.168.1.50 \
    --server-port 1883
```

---

### 2. `levoit_local_cloud.py`
A lightweight local TLS MQTT responder and HTTP OTA server:
1. **Cloud-Free Handshake:** Emulates the VeSync cloud MQTT broker on port 1883, granting `CONNACK` and `SUBACK` for `mqtt/<cid>/v2/rsp` and `mqtt/<cid>/v2/bypass`. This signals the purifier that onboarding is successful, causing it to write Wi-Fi credentials to NVS flash.
2. **ESPHome Header Wrapper:** Prepend the required 128-byte VeSync `.rel.bin` OTA header (with MD5 hash and version `2.0.00`) to any compiled ESPHome `.bin` so stock firmware accepts it over OTA.
3. **Wireless Local OTA:** Issues the `bypassV2` $\rightarrow$ `upFirmware` MQTT command and serves the firmware binary over HTTP on port 18080.

#### Flashing ESPHome Wirelessly over Local Wi-Fi:
```bash
# 1. Package ESPHome binary with VeSync OTA container:
python3 levoit_local_cloud.py \
    --wrap-esphome esphome-factory.bin esphome_wrapped.rel.bin \
    --new-version 2.0.00

# 2. Launch the local MQTT responder with the OTA file attached:
python3 levoit_local_cloud.py \
    --server-ip 192.168.1.50 \
    --ota-file esphome_wrapped.rel.bin \
    --plugin mainFw \
    --new-version 2.0.00
```
When the purifier connects, the update command is dispatched automatically. The device flashes ESPHome to its OTA partition and reboots into ESPHome without requiring hardware disassembly.

---

### 3. `levoit_enumerate_firmware.py`
Scans and catalogues official firmware binaries from VeSync's CDN servers (`http://fw.vesync.com`):
* **Direct Probing (No Account Needed):** Concurrently scans models (Core 200S, 300S, 400S, 600S, EverestAir in EU and US variants) and versions, verifying HTTP availability and reading the 128-byte VeSync `.rel.bin` header (MD5, hardware version, software version, target model).
* **Cloud API Mode (Optional):** Logs into your VeSync account (`--user` and `--password`) to query `/cloud/v2/deviceManaged/getFirmwareUpdateInfoList` for live update metadata across paired devices.
* **JSON Export:** Save results directly to a structured JSON file (`-o catalog.json`).

#### Usage:
```bash
# Scan all Core 300S models on fw.vesync.com:
python3 levoit_enumerate_firmware.py --models Core300s

# Scan all models and export catalog to JSON:
python3 levoit_enumerate_firmware.py -o firmware_catalog.json
```
