# Levoit Air Purifier Local Tooling & Instructions

This folder contains standalone Python tools to configure, wirelessly flash ESPHome, and restore factory stock firmware on Levoit Air Purifiers (such as the **Core 300S**, **Core 200S**, **Core 400S**, and **Core 600S**), **completely without a VeSync cloud account**.

---

## Table of Contents
1. [Prerequisites & Installation](#prerequisites--installation)
2. [Quick Start: Interactive Onboarding Wizard](#quick-start-interactive-onboarding-wizard)
3. [Step-by-Step Instructions](#step-by-step-instructions)
   * [Step 1: Put Purifier into Pairing Mode](#step-1-put-purifier-into-pairing-mode)
   * [Scenario A: Initial ESPHome Flash (Stock $\rightarrow$ ESPHome)](#scenario-a-initial-esphome-flash-stock-%E2%86%92-esphome)
   * [Scenario B: Cloud-Free Wi-Fi Provisioning Only (Keep Stock)](#scenario-b-cloud-free-wi-fi-provisioning-only-keep-stock)
   * [Scenario C: Restoring Stock Firmware (ESPHome $\rightarrow$ Stock)](#scenario-c-restoring-stock-firmware-esphome-%E2%86%92-stock)
   * [Scenario D: Scanning VeSync CDN Firmwares](#scenario-d-scanning-vesync-cdn-firmwares)
4. [Command-Line Reference](#command-line-reference)
5. [Troubleshooting & FAQs](#troubleshooting--faqs)

---

## Prerequisites & Installation

### 1. Requirements
* Python 3.8 or higher.
* Bluetooth Low Energy (BLE) hardware on your host computer (laptop or Bluetooth USB dongle).
* 2.4 GHz Wi-Fi network (the ESP32 does not support 5 GHz Wi-Fi).

### 2. Install Dependencies
Open a terminal in this directory (or the repository root) and install the required Python packages:

```bash
pip install -r requirements.txt
```

*(Optional: If you plan to use serial recovery flashing via USB-to-UART, install `esptool`: `pip install esptool`)*

### 3. Operating System Notes
* **macOS:** Grant Bluetooth permission to your terminal app in **System Settings $\rightarrow$ Privacy & Security $\rightarrow$ Bluetooth**.
* **Linux:** Ensure your user belongs to the `bluetooth` or `dialout` group (or run with appropriate Bluetooth permissions).

---

## Quick Start: Interactive Onboarding Wizard

The simplest way to use these tools is the interactive wizard:

```bash
python3 levoit_onboard.py
```
*(or `python3 tools/levoit_onboard.py` if running from repo root)*

The wizard will:
1. **Auto-detect your computer's LAN IPv4 address** (e.g., `192.168.1.50`).
2. Display an interactive menu:
   ```text
   ======================================================================
           Levoit Core 300S Onboarding & Firmware Manager
   ======================================================================
   Auto-detected Host LAN IP: 192.168.1.50

   Please choose an operation:
     [1] Initial Flash: Install ESPHome on Stock Levoit Purifier (BLE + OTA)
     [2] Wi-Fi Provisioning Only (Keep Stock Firmware, Cloud-Free BLE Setup)
     [3] Restore Factory Stock Firmware to ESPHome Device (OTA / Web / Serial)
     [4] Wrap ESPHome binary into VeSync .rel.bin container
     [5] Exit
   ======================================================================
   ```
3. Prompt for your Wi-Fi SSID and Password (with secure masked password entry).

---

## Step-by-Step Instructions

### Step 1: Put Purifier into Pairing Mode
Before running any BLE operation, put your Levoit air purifier into active BLE pairing mode:
1. Plug the purifier into AC mains power and turn it on.
2. **Press and hold the Wi-Fi icon button** (or on some models, the Power button) **for 5 to 10 seconds** until the purifier emits a beep and the **Wi-Fi LED indicator flashes rapidly**.
3. The purifier is now in active network configuration pairing mode (`netcfg` active) and advertising via BLE.

> [!NOTE]
> Even if the device was previously plugged in, it remains in an "idle" BLE mode until the Wi-Fi button is held for 5 seconds. The tool will automatically detect if the device is found in idle mode and prompt you in real time to hold the button.

---

### Scenario A: Initial ESPHome Flash (Stock $\rightarrow$ ESPHome)

This completely replaces the factory firmware with ESPHome wirelessly over local Wi-Fi. **No screwdriver or disassembly required.**

#### 1. Compile ESPHome Firmware
Compile your ESPHome configuration (e.g. `sample-levoit-300s-configuration.yaml`):
```bash
esphome compile sample-levoit-300s-configuration.yaml
```
Locate the generated `.factory.bin` or `.bin` binary (usually at `.esphome/build/<device-name>/.pioenvs/<device-name>/firmware.factory.bin`).

#### 2. Run the Automated Flasher
Execute the flasher pointing to your compiled binary:
```bash
python3 levoit_onboard.py --flash-esphome path/to/firmware.factory.bin
```
*(If `--ssid` or `--password` are not provided on the command line, the tool will interactively prompt for them).*

#### What happens automatically:
1. **Wraps the Binary:** Adds the 128-byte VeSync `.rel.bin` OTA container header (MD5 checksum + version `2.0.00`).
2. **Starts Local Cloud:** Spins up an encrypted TLS MQTT responder (port 1883) and HTTP OTA server (port 18080) in the background.
3. **BLE Key Exchange:** Pairs with the purifier via BLE using Protocol v1 (RSA-1024/AES-128) or Protocol v2 (`HIGH_SECURITY_WIFI_BLE` Diffie-Hellman + dynamic $K_1$/$K_2$ session keys).
4. **Provisions Wi-Fi:** Sends Wi-Fi credentials pointing the purifier's MQTT server to your computer.
5. **OTA Trigger & Flashing:** When the purifier connects to Wi-Fi and connects to your local MQTT broker, the tool issues the `upFirmware` command. The purifier downloads the ESPHome binary over HTTP, verifies MD5, writes to flash, and reboots directly into ESPHome!

> [!NOTE]
> **Protocol v2 Factory Production Key Exchange (`has_org_key=1`):**
> On newer stock firmware (v2.0.00 / Protocol v2), factory units burn an encrypted `prd_origin_key` in NVS. During the initial BLE handshake (`0x4201` $\rightarrow$ `0x4202` $\rightarrow$ `0x4203`), the tool queries VeSync's Cloud API once (`/iot/api/deviceManaged/v1/getConfigKeyV1`) to obtain the temporary session key $K_2$. The tool will automatically prompt for your VeSync account (or accept `--vesync-email` and `--vesync-password`). Once authenticated over BLE, the purifier is pointed exclusively to your local machine, and all subsequent Wi-Fi and OTA flashing occur completely offline.

---

### Scenario B: Cloud-Free Wi-Fi Provisioning Only (Keep Stock)

If you wish to keep stock Levoit firmware but want to connect the purifier to your home Wi-Fi **without creating a VeSync cloud account**:

```bash
python3 levoit_onboard.py
# Choose option [2]
```
Or via CLI:
```bash
python3 levoit_ble_provision.py --ssid "MyHomeWiFi" --password "MySecretPassword"
```

> [!NOTE]
> Stock firmware normally discards Wi-Fi credentials unless it receives a mandatory MQTT `SUBACK` check. This tool starts a background TLS responder that automatically responds with `CONNACK` and `SUBACK`, causing the purifier to commit credentials to NVS flash permanently.

---

### Scenario C: Restoring Stock Firmware (ESPHome $\rightarrow$ Stock)

If you have a purifier currently running ESPHome and want to return to 100% factory Levoit firmware, you can restore it wirelessly or over serial.

#### 1. Over the Network via ESPHome Native OTA (Port 3232 - Recommended)
If the purifier is powered on and connected to your Wi-Fi running ESPHome:
```bash
python3 levoit_onboard.py --restore-stock --device-ip 192.168.1.55
```
*(If you set an OTA password in your ESPHome YAML, add `--ota-password "your_password"`).*

#### 2. Over the Network via ESPHome Web Server (Port 80)
If your ESPHome configuration includes `web_server:`:
```bash
python3 levoit_onboard.py --restore-stock --restore-method web --device-ip 192.168.1.55
```

#### 3. Over USB Serial UART (`esptool.py`)
If you have connected a 3.3V USB-to-UART adapter to the logic board (`TXD0`, `RXD0`, `GND`):
```bash
python3 levoit_onboard.py --restore-stock --restore-method serial --serial-port /dev/cu.usbserial-0001
```

#### 4. Extract Clean ESP-IDF Binary Only
If you prefer to manually upload the stock binary through the Home Assistant ESPHome Dashboard UI:
```bash
python3 levoit_onboard.py --restore-stock --restore-method extract
```
This saves a clean `Core300s_EU_stock_app.bin` ready to upload.

> [!TIP]
> **Automatic Header Stripping & CDN Download:**
> ESPHome's OTA component rejects VeSync `.rel.bin` containers because they start with a 128-byte header instead of the ESP magic byte `0xE9`. Our tool automatically detects `.rel.bin` containers and slices the 128-byte header to recover the clean ESP-IDF binary. If you do not have a stock firmware file locally, the tool will offer to download the official v2.0.00 firmware directly from VeSync's CDN.

---

### Scenario D: Scanning VeSync CDN Firmwares

Use `levoit_enumerate_firmware.py` to scan Levoit's official CDN servers (`http://fw.vesync.com`) for available stock firmware binaries across models and versions:

```bash
# Scan Core 300S models:
python3 levoit_enumerate_firmware.py --models Core300s

# Scan all models (Core 200S, 300S, 400S, 600S) and export results to JSON:
python3 levoit_enumerate_firmware.py -o firmware_catalog.json
```

---

## Command-Line Reference

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--flash-esphome <bin>` | Wrap binary, start local cloud, and perform one-command initial flash | `None` |
| `--restore-stock [file]` | Restore stock firmware on ESPHome device (auto-strips 128B header or fetches from CDN) | `None` |
| `--restore-method` | Method for `--restore-stock`: `native` (port 3232), `web` (port 80), `serial`, `extract` | `native` |
| `--device-ip <ip>` | IP address of ESPHome device on your LAN (for `--restore-stock`) | Prompts |
| `--ota-password <pwd>` | Password for ESPHome OTA authentication (if enabled) | `None` |
| `--ssid <ssid>` | Wi-Fi network SSID (2.4 GHz) | Prompts |
| `--password <pwd>` | Wi-Fi network password (masked if prompted) | Prompts |
| `--server-ip <ip>` | Local host IP for MQTT and HTTP servers | **Auto-detected** |
| `--server-port <port>` | Local TLS MQTT port | `1883` |
| `--http-port <port>` | Local HTTP OTA server port | `18080` |
| `--mac <mac>` | Hardware BLE MAC (`AA:BB:CC:DD:EE:FF`), needed on macOS for v2.x if UUID hides MAC | Prompts if needed |
| `--proto-ver <1\|2>` | Force BLE protocol version (1 for fw v1.x, 2 for fw v2.x) | Auto-detected |
| `--vesync-email <email>` | VeSync account email for Protocol v2 factory production key exchange | Prompts if needed |
| `--vesync-password <pwd>` | VeSync account password for Protocol v2 factory production key exchange | Prompts if needed |
| `--country-code <code>` | VeSync account region/country code (`EU` or `US`) | `EU` |
| `--wrap-esphome <in> <out>`| Wrap an ESPHome binary with VeSync `.rel.bin` container and exit | `None` |

---

## Troubleshooting & FAQs

### 1. Purifier not discovered or waiting for pairing mode
* **Cause:** Purifier is not in active pairing mode (idle state) or Bluetooth is out of range.
* **Fix:** Turn on the purifier, then press and hold the **Wi-Fi button for 5 to 10 seconds** until the purifier beeps and the Wi-Fi icon flashes rapidly. The tool will automatically detect the state change and connect immediately.

### 2. Hardware BLE MAC Address Extraction
* **Note:** On macOS, CoreBluetooth hides raw 6-byte MAC addresses behind UUIDs. The tool **automatically extracts the true 6-byte hardware MAC address** directly from manufacturer advertisement payload bytes `[1:7]`, so manual `--mac` input is no longer required in normal operation. If you ever need to override it, you can pass `--mac AA:BB:CC:DD:EE:FF`.

### 3. Port 1883 is already in use
* **Cause:** Another MQTT broker (such as Mosquitto or Home Assistant MQTT add-on) is already running on port 1883 on your computer.
* **Fix:** Temporarily stop Mosquitto (`sudo systemctl stop mosquitto` or `brew services stop mosquitto`), or pass a custom port: `--server-port 8883`.

### 4. Device connects to Wi-Fi but does not download OTA image
* **Cause:** Host machine firewall is blocking incoming connections on port 1883 (MQTT) or port 18080 (HTTP).
* **Fix:** Temporarily allow incoming connections or disable local firewall rules on ports 1883 and 18080.
