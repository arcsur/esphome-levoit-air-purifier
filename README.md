# Levoit Air Purifier Integration for ESPHome

ESPHome custom component for **Levoit Smart Air Purifiers** (Core 200S, Core 300S, Core 400S, Core 600S) featuring:
* Full local control over fan speeds, auto modes, display lock, nightlight, and PM2.5 air quality metrics.
* **100% Cloud-Free Onboarding:** Pair and connect your purifier to your local Wi-Fi network without creating a VeSync cloud account.
* **No-Screwdriver Wireless OTA Flashing:** Flash ESPHome directly over local Wi-Fi from stock VeSync firmware without opening the purifier case.
* **Dual-Controller DFU Support:** Tools to update both the ESP32 and the secondary SinOne SC95F8616 Sub-MCU appliance controller.

---

## Supported Devices
* **Levoit Core 200S** (Confirmed)
* **Core 300S** (Confirmed, including Amazon EU 240V models)
* **Core 400S** (Confirmed)
* **Core 600S** (Confirmed)

---

## Tools Added

### 1. Interactive Onboarding & Initial ESPHome Flashing Wizard
We provide an all-in-one wizard [`tools/levoit_onboard.py`](tools/levoit_onboard.py) (and [`tools/levoit_ble_provision.py`](tools/levoit_ble_provision.py)) that makes initial flashing and provisioning effortless:

* **Interactive Prompts:** Prompts for Wi-Fi SSID and password (with masked password entry) if omitted from CLI flags.
* **Automatic IP Detection:** Automatically determines your local host IPv4 address (`192.168.x.x`) without needing `--server-ip`.
* **One-Command Initial Flash:** Wraps your compiled ESPHome binary with the required VeSync 128-byte header, spins up a local TLS MQTT broker and HTTP OTA server in the background, pairs over BLE, sets Wi-Fi, triggers wireless flashing, and reboots the purifier into ESPHome!

```bash
# Interactive wizard:
python3 tools/levoit_onboard.py

# Or one-line automated initial flash:
python3 tools/levoit_onboard.py --flash-esphome firmware.factory.bin
```

---

### 2. Restore Factory Stock Firmware (From ESPHome)
If you have a purifier currently running ESPHome and wish to return to factory stock Levoit firmware, [`tools/levoit_onboard.py`](tools/levoit_onboard.py) can restore it wirelessly or over serial:

```bash
# Wireless restore via ESPHome Native OTA (Port 3232 - Recommended):
python3 tools/levoit_onboard.py --restore-stock --device-ip 192.168.1.55

# Wireless restore via ESPHome Web Server (Port 80 HTTP /update):
python3 tools/levoit_onboard.py --restore-stock --restore-method web --device-ip 192.168.1.55

# Wired restore via USB Serial (esptool.py):
python3 tools/levoit_onboard.py --restore-stock --restore-method serial --serial-port /dev/cu.usbserial-0001
```

> [!NOTE]
> The tool automatically recognizes VeSync `.rel.bin` containers and slices the 128-byte header so that ESPHome's OTA component accepts the clean `0xE9` ESP magic byte. If no local stock firmware is present, the tool offers to download the official Core 300S EU v2.0.00 firmware directly from VeSync's CDN.

---

### 3. Cloud-Free Local BLE Pairing & Wi-Fi Provisioning
Stock firmware discards Wi-Fi credentials sent via BLE unless the device connects to an MQTT broker and receives `SUBACK` for both `mqtt/<cid>/v2/rsp` and `mqtt/<cid>/v2/bypass`.

Our tool performs the complete BLE key exchange (supporting both Protocol v1 RSA/AES and Protocol v2 `HIGH_SECURITY_WIFI_BLE` DH + dynamic $K_1$/$K_2$ session key derivation) and runs a background TLS MQTT responder so credentials persist to NVS flash without ever contacting VeSync cloud:
```bash
python3 tools/levoit_ble_provision.py --ssid "YourWiFiSSID" --password "YourWiFiPassword"
```

---

### 4. Standalone Local Cloud & Dual-Controller OTA Flasher
[`tools/levoit_local_cloud.py`](tools/levoit_local_cloud.py) provides modular control for advanced setups:
* Wrap ESPHome binaries: `python3 tools/levoit_local_cloud.py --wrap-esphome in.bin out.rel.bin`
* Push Main MCU (ESP32) OTA: `python3 tools/levoit_local_cloud.py --ota-file out.rel.bin --plugin mainFw`
* Push Sub-MCU (SC95F8616) OTA: `python3 tools/levoit_local_cloud.py --ota-file mcuFw-C2.bin --plugin mcuFw-C2`

---

### 4. Official Firmware Enumerator
Scan VeSync's CDN servers (`http://fw.vesync.com`) for official firmware binaries across models and versions:
```bash
python3 tools/levoit_enumerate_firmware.py --models Core300s
```

---

## Serial Flashing (Alternative / Hard Disassembly Method)
If you prefer hardware flashing or need unbricking recovery:
1. Place device upside down and remove base cover and filter (4 to 8 screws depending on model).
2. Carefully separate the base and top using a pry tool and unplug the logic board.
3. Solder wires to `TXD0`, `RXD0`, `IO0`, `+3V3`, and `GND` near the ESP32 on the logic board, and connect to a 3.3V USB-UART adapter.
4. Pull `IO0` to GND while powering on to enter download mode.
5. Backup, erase, and flash:
   ```bash
   esptool.py read_flash 0 ALL levoit-stock-backup.bin
   esptool.py erase_flash
   esptool.py write_flash 0x00 firmware.factory.bin
   ```

---

## Technical Documentation & Protocols
* [Levoit Core 300S Firmware Reverse-Engineering Analysis](docs/levoit_300s_firmware_analysis.md)
* [SinOne SC95F8616 Main Controller MCU UART DFU Protocol](docs/SUB_MCU_UART_DFU_PROTOCOL.md)
* [Local Provisioning & OTA Tools Guide](tools/README.md)

---

## Configuration Example
See [`sample-levoit-300s-configuration.yaml`](sample-levoit-300s-configuration.yaml) for a complete working ESPHome configuration for the Core 300S (compatible with Core 400S).

---

## Contributors
* Aiden (@acvigue) - Original component & Core 300S support
* Ryan Lang (@ryan-lang) - Core 400S support
* Havarius (@Havarius) - Core 200S support
* Haydon (@haydonryan) - Documentation & testing
* @arcsur - Cloud-free onboarding, local OTA tooling, firmware enumerator, and Sub-MCU UART DFU protocol reverse-engineering
