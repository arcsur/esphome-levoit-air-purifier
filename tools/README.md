# Levoit Air Purifier Local Pairing, Flashing & Restore Tooling

This directory contains standalone Python tools to configure, wirelessly flash ESPHome, and restore stock firmware on Levoit Air Purifiers (such as the Core 300S EU 240V model) **completely without a VeSync cloud account**.

---

## Quick Start: Interactive Onboarding Wizard

Simply run the onboarding tool with no arguments:

```bash
python3 tools/levoit_onboard.py
```
*(or `python3 tools/levoit_ble_provision.py`)*

The tool automatically:
1. **Detects your local host IPv4 address** on your LAN (e.g. `192.168.1.50`).
2. Interactively prompts for your Wi-Fi SSID and Password (with secure masked password entry).
3. Offers a simple menu:
   * **[1] Initial ESPHome Flash:** Automates the complete flow (VeSync header wrapping, background TLS MQTT responder, HTTP OTA server, BLE pairing, Wi-Fi provisioning, and wireless flash).
   * **[2] Wi-Fi Provisioning Only:** Pairs over BLE and persists Wi-Fi credentials to NVS flash while keeping stock firmware.
   * **[3] Restore Factory Stock Firmware:** Restores original Levoit firmware to a device currently running ESPHome via Native OTA (port 3232), Web Server (port 80), or USB-UART serial.
   * **[4] Wrap ESPHome Binary:** Generates a 128-byte `.rel.bin` VeSync container for manual OTA.

---

## Tools

### 1. `levoit_onboard.py` / `levoit_ble_provision.py`

#### Initial Flash (Stock $\rightarrow$ ESPHome) in One Command:
```bash
python3 tools/levoit_onboard.py --flash-esphome firmware.factory.bin
```
*(If `--ssid` or `--password` are omitted, the tool interactively prompts for them; `--server-ip` defaults automatically to your machine's local IP).*

#### Restoring Factory Stock Firmware (ESPHome $\rightarrow$ Stock):
If you have an air purifier currently running ESPHome and want to revert to factory Levoit firmware:
```bash
# 1. Over the Network via ESPHome Native OTA (Port 3232 - Recommended):
python3 tools/levoit_onboard.py --restore-stock --device-ip 192.168.1.55

# 2. Over the Network via ESPHome Web Server (Port 80 HTTP /update):
python3 tools/levoit_onboard.py --restore-stock --restore-method web --device-ip 192.168.1.55

# 3. Over USB Serial UART:
python3 tools/levoit_onboard.py --restore-stock --restore-method serial --serial-port /dev/cu.usbserial-0001

# 4. Extract clean ESP-IDF .bin file for manual dashboard upload:
python3 tools/levoit_onboard.py --restore-stock --restore-method extract
```
> [!NOTE]
> The restore tool automatically detects whether you pass a VeSync `.rel.bin` container or a clean `.bin` file, and strips the 128-byte VeSync header so ESPHome's OTA validator accepts the `0xE9` ESP magic byte. If no local firmware file is found, it offers to download the official v2.0.00 firmware directly from VeSync's CDN server.

#### Standalone Wi-Fi Provisioning (Keep Stock Firmware):
```bash
python3 tools/levoit_ble_provision.py \
    --ssid "YourWiFiSSID" \
    --password "YourWiFiPassword"
```
Supports both **Protocol v1** (AES-128 / RSA-1024) and **Protocol v2** (`HIGH_SECURITY_WIFI_BLE` Diffie-Hellman + dynamic $K_1$/$K_2$ session key generation used in firmware `v2.0.00`). Runs a background TLS MQTT responder so the purifier receives its mandatory `SUBACK` check and writes credentials to NVS flash.

---

### 2. `levoit_local_cloud.py`
A lightweight local TLS MQTT responder and HTTP OTA server for advanced or modular workflows:
1. **Cloud-Free Handshake:** Emulates the VeSync cloud MQTT broker on port 1883, granting `CONNACK` and `SUBACK` for `mqtt/<cid>/v2/rsp` and `mqtt/<cid>/v2/bypass`.
2. **ESPHome Header Wrapper:** Prepend the required 128-byte VeSync `.rel.bin` OTA header (with MD5 hash and version `2.0.00`) to any compiled ESPHome `.bin`:
   ```bash
   python3 tools/levoit_local_cloud.py --wrap-esphome in.bin out.rel.bin
   ```
3. **Standalone Local OTA Server:**
   ```bash
   python3 tools/levoit_local_cloud.py --ota-file out.rel.bin --plugin mainFw
   ```
   *(Defaults `--server-ip` automatically to your host machine's IP).*

---

### 3. `levoit_enumerate_firmware.py`
Scans and catalogues official firmware binaries from VeSync's CDN servers (`http://fw.vesync.com`):
* **Direct Probing (No Account Needed):** Concurrently scans models (Core 200S, 300S, 400S, 600S, EverestAir in EU and US variants) and versions, verifying HTTP availability and reading the 128-byte VeSync `.rel.bin` header (MD5, hardware version, software version, target model).
* **JSON Export:** Save results directly to a structured JSON file (`-o catalog.json`).

#### Usage:
```bash
# Scan all Core 300S models on fw.vesync.com:
python3 tools/levoit_enumerate_firmware.py --models Core300s

# Scan all models and export catalog to JSON:
python3 tools/levoit_enumerate_firmware.py -o firmware_catalog.json
```
