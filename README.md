# Levoit Air Purifier Integration for ESPHome

ESPHome custom component for **Levoit Smart Air Purifiers** (Core 200S, Core 300S, Core 400S, Core 600S) featuring:
* Full local control over fan speeds, auto modes, display lock, nightlight, and PM2.5 air quality metrics.
* **100% Cloud-Free Onboarding:** Pair and connect your purifier to your local Wi-Fi network without creating a VeSync cloud account.
* **No-Screwdriver Wireless OTA Flashing:** Flash ESPHome directly over local Wi-Fi from stock VeSync firmware without opening the purifier case.
* **Dual-Controller Architecture & Sub-MCU Firmware Updates:** Exposes the SinOne SC95F8616 Main Appliance Controller MCU as a native Home Assistant `update` entity, allowing appliance motor/sensor firmware updates over the internal UART bus directly from Home Assistant.

---

## Supported Devices
* **Levoit Core 200S** (Confirmed)
* **Core 300S** (Confirmed, including Amazon EU 240V models)
* **Core 400S** (Confirmed)
* **Core 600S** (Confirmed)

---

## Features Added in This Fork

### 1. Native Home Assistant Sub-MCU Firmware Update Entity
Levoit purifiers contain two microcontrollers:
1. **Espressif ESP32-SOLO-1C:** Connectivity and smart features (running ESPHome).
2. **SinOne SC95F8616 (Main Controller MCU):** Controls the BLDC fan motor, capacitive touch buttons, LED display ring, and PM2.5 laser particle sensor.

This fork adds the `update` platform (`components/levoit/update/`), which registers the Main Controller MCU in Home Assistant:
* **Current Version:** Extracted directly from live UART status packets.
* **Update Notifications:** Blue "Update Available" badge when a newer MCU binary is hosted.
* **One-Click Install:** Flashes the SC95F8616 over UART (115200 8N1) using the reverse-engineered 5-step DFU state machine (`0x8030` start, `0x8031` chunk pull, `0x8032` download verify, `0x8033` flash verify, `0xD101` reset) and reports live progress in Home Assistant.

```yaml
# Add to your purifier YAML configuration:
update:
  - platform: levoit
    name: "Main MCU Firmware"
    # Optional: specify URL hosting the raw SC95F8616 binary
    # source_url: "http://192.168.1.50:18080/mcu_fw.bin"
    # latest_version: "1.0.08"
```

### 2. Cloud-Free Local Pairing & Wi-Fi Provisioning
Stock firmware discards Wi-Fi credentials sent via BLE unless the device connects to an MQTT broker and receives `SUBACK` for both `mqtt/<cid>/v2/rsp` and `mqtt/<cid>/v2/bypass`.

Our standalone tool [`tools/levoit_ble_provision.py`](tools/levoit_ble_provision.py) performs the complete BLE key exchange (supporting both Protocol v1 RSA/AES and Protocol v2 `HIGH_SECURITY_WIFI_BLE` DH + dynamic $K_1$/$K_2$ session key derivation) and redirects the MQTT broker to your local machine:
```bash
python3 tools/levoit_ble_provision.py \
    --ssid "YourWiFiSSID" \
    --password "YourWiFiPassword" \
    --server-ip 192.168.1.50 \
    --server-port 1883
```

### 3. Wireless Local OTA Flashing (No Disassembly Needed)
Using [`tools/levoit_local_cloud.py`](tools/levoit_local_cloud.py), you can push an ESPHome binary wirelessly over your local network:
```bash
# 1. Wrap compiled ESPHome factory binary with the 128-byte VeSync .rel.bin header:
python3 tools/levoit_local_cloud.py \
    --wrap-esphome firmware.factory.bin esphome_wrapped.rel.bin \
    --new-version 2.0.00

# 2. Run local responder to accept device connection and trigger OTA:
python3 tools/levoit_local_cloud.py \
    --server-ip 192.168.1.50 \
    --ota-file esphome_wrapped.rel.bin \
    --plugin mainFw \
    --new-version 2.0.00
```
The device connects, commits Wi-Fi to NVS flash, receives the `upFirmware` command, downloads the image over HTTP, and reboots directly into ESPHome.

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
* @arcsur - Cloud-free onboarding, local OTA tooling, Main Controller MCU UART DFU protocol reverse-engineering, and Home Assistant `update` entity platform
