#pragma once

/**
 * Levoit Core 300S Main Controller (SinOne SC95F8616 MCU) UART DFU Flasher
 * =======================================================================
 * Reverse-engineered from official Levoit Core 300S v2.0.00 firmware:
 *   - vesync_ota_mcu_start    @ 0x400e7dbc (OpCode 0x8030 -> wire 0x013080)
 *   - ota_mcu_bin_requst      @ 0x400e7b9c (OpCode 0x8031 -> wire 0x013180)
 *   - ota_mcu_dl_result_report@ 0x400e7b9c (OpCode 0x8032 -> wire 0x013280)
 *   - ota_mcu_result_report   @ 0x400e7b9c (OpCode 0x8033 -> wire 0x013380)
 *   - purifier_uart_reboot_mcu@ 0x400d9528 (OpCode 0xD101 -> wire 0x0101D1)
 *
 * Wire Framing:
 *   UART 115200 8N1 (GPIO17 TX, GPIO16 RX)
 *   Outer Frame:
 *     [0] = 0xA5
 *     [1] = PacketType (0x22 CMD, 0x12 ACK)
 *     [2] = Sequence number
 *     [3..4] = Payload length (LE16) = len(inner)
 *     [5] = Checksum = 0xFF ^ (sum(frame[0..4] + inner) & 0xFF)
 *   Inner Payload:
 *     [0..3] = 0x01, (opcode & 0xFF), (opcode >> 8), 0x00
 *     [4..]  = Opcode-specific arguments
 */

#include <cstdint>
#include <vector>
#include <functional>
#include <cstring>
#include <algorithm>

namespace esphome {
namespace levoit {

enum class McuOtaState : uint8_t {
  IDLE = 0,
  START_SENT = 1,
  CHUNKS_TRANSFER = 2,
  WAIT_DL_RESULT = 3,
  WAIT_FLASH_RESULT = 4,
  SUCCESS = 5,
  FAILED = 6
};

class LevoitMcuOta {
 public:
  using SendUartFrameFn = std::function<void(const std::vector<uint8_t> &raw_packet)>;
  using ProgressFn = std::function<void(size_t written, size_t total, float percentage)>;
  using CompletionFn = std::function<void(bool success, const char *message)>;

  LevoitMcuOta(SendUartFrameFn send_fn) : send_raw_(send_fn) {}

  void set_progress_callback(ProgressFn cb) { progress_cb_ = cb; }
  void set_completion_callback(CompletionFn cb) { completion_cb_ = cb; }

  bool start_update(const uint8_t *mcu_bin, size_t bin_size, uint8_t v_major = 1, uint8_t v_minor = 0, uint8_t v_patch = 0) {
    if (state_ != McuOtaState::IDLE) {
      if (completion_cb_) completion_cb_(false, "MCU OTA is already in progress");
      return false;
    }
    if (!mcu_bin || bin_size == 0 || bin_size > 65536) {
      if (completion_cb_) completion_cb_(false, "Invalid MCU binary size (max 64KB)");
      return false;
    }

    bin_data_ = mcu_bin;
    bin_size_ = bin_size;
    ver_major_ = v_major;
    ver_minor_ = v_minor;
    ver_patch_ = v_patch;
    state_ = McuOtaState::START_SENT;
    mtu_ = 512; // Default, clamped to <= 1024 once MCU replies

    // OpCode 0x8030 payload: [0x00, 0x04, ver_maj, ver_min, ver_patch, size_b0..b3, 0xFF, 0xFF] (11 bytes)
    std::vector<uint8_t> args(11, 0x00);
    args[0] = 0x00; // Channel 0
    args[1] = 0x04; // Version len
    args[2] = ver_major_;
    args[3] = ver_minor_;
    args[4] = ver_patch_;
    args[5] = static_cast<uint8_t>(bin_size_ & 0xFF);
    args[6] = static_cast<uint8_t>((bin_size_ >> 8) & 0xFF);
    args[7] = static_cast<uint8_t>((bin_size_ >> 16) & 0xFF);
    args[8] = static_cast<uint8_t>((bin_size_ >> 24) & 0xFF);
    args[9] = 0xFF;
    args[10] = 0xFF;

    send_frame(0x8030, 0x22, args);
    return true;
  }

  /**
   * Feed incoming UART messages decoded by the transport layer
   * @param packet_type 0x22 (CMD) or 0x12 (ACK)
   * @param seq Frame sequence number
   * @param opcode 16-bit internal opcode (e.g. 0x8030, 0x8031, etc.)
   * @param payload Arguments after the 4-byte transport header
   * @param payload_len Length of arguments
   */
  void on_uart_message(uint8_t packet_type, uint8_t seq, uint16_t opcode, const uint8_t *payload, size_t payload_len) {
    if (state_ == McuOtaState::IDLE) return;

    if (opcode == 0x8030) {
      // MCU responds to Start with ACK (0x12) or 0x8036 resume:
      // payload[0] = status (0x00 = ready)
      // payload[1..2] = requested MTU (LE16)
      if (payload_len >= 3 && payload[0] == 0x00) {
        uint16_t req_mtu = payload[1] | (static_cast<uint16_t>(payload[2]) << 8);
        mtu_ = std::min<uint16_t>(req_mtu ? req_mtu : 512, 1024);
        state_ = McuOtaState::CHUNKS_TRANSFER;
      } else {
        fail("MCU rejected OTA start");
      }
    } else if (opcode == 0x8031) {
      // MCU requests binary chunk:
      // payload[0..3] = requested offset (LE32)
      if (payload_len >= 4 && state_ == McuOtaState::CHUNKS_TRANSFER) {
        uint32_t offset = payload[0] |
                          (static_cast<uint32_t>(payload[1]) << 8) |
                          (static_cast<uint32_t>(payload[2]) << 16) |
                          (static_cast<uint32_t>(payload[3]) << 24);

        if (offset >= bin_size_) {
          // Out of range offset
          std::vector<uint8_t> err_resp = {0x02, 0, 0, 0, 0, 0, 0};
          send_frame(0x8031, 0x12, err_resp, seq);
          return;
        }

        uint32_t rem = bin_size_ - offset;
        uint16_t chunk_len = std::min<uint16_t>(rem, mtu_);
        bool is_last = (rem <= mtu_);

        // Response header: [is_last (1B), offset (4B LE), chunk_len (2B LE), data (chunk_len B)]
        std::vector<uint8_t> chunk_resp(7 + chunk_len);
        chunk_resp[0] = is_last ? 0x01 : 0x00;
        chunk_resp[1] = static_cast<uint8_t>(offset & 0xFF);
        chunk_resp[2] = static_cast<uint8_t>((offset >> 8) & 0xFF);
        chunk_resp[3] = static_cast<uint8_t>((offset >> 16) & 0xFF);
        chunk_resp[4] = static_cast<uint8_t>((offset >> 24) & 0xFF);
        chunk_resp[5] = static_cast<uint8_t>(chunk_len & 0xFF);
        chunk_resp[6] = static_cast<uint8_t>((chunk_len >> 8) & 0xFF);
        std::memcpy(&chunk_resp[7], bin_data_ + offset, chunk_len);

        send_frame(0x8031, 0x12, chunk_resp, seq);

        if (progress_cb_) {
          size_t written = offset + chunk_len;
          float pct = (static_cast<float>(written) / static_cast<float>(bin_size_)) * 100.0f;
          progress_cb_(written, bin_size_, pct);
        }

        if (is_last) {
          state_ = McuOtaState::WAIT_DL_RESULT;
        }
      }
    } else if (opcode == 0x8032) {
      // MCU download result report:
      // payload[0] = status (0x00 = success)
      std::vector<uint8_t> ack_resp;
      send_frame(0x8032, 0x12, ack_resp, seq);
      if (payload_len >= 1 && payload[0] == 0x00) {
        state_ = McuOtaState::WAIT_FLASH_RESULT;
      } else {
        fail("MCU reported download verification error");
      }
    } else if (opcode == 0x8033) {
      // MCU flash result report:
      // payload[0] = status (0x00 = success)
      std::vector<uint8_t> ack_resp;
      send_frame(0x8033, 0x12, ack_resp, seq);
      if (payload_len >= 1 && payload[0] == 0x00) {
        state_ = McuOtaState::SUCCESS;
        // Send MCU reboot command (OpCode 0xD101, payload {0x01})
        std::vector<uint8_t> reboot_arg = {0x01};
        send_frame(0xD101, 0x22, reboot_arg);
        if (completion_cb_) {
          completion_cb_(true, "Main MCU upgraded and rebooted successfully");
        }
        state_ = McuOtaState::IDLE;
      } else {
        fail("MCU reported flash burning failure");
      }
    }
  }

  McuOtaState get_state() const { return state_; }

 private:
  void fail(const char *reason) {
    state_ = McuOtaState::FAILED;
    if (completion_cb_) completion_cb_(false, reason);
    state_ = McuOtaState::IDLE;
  }

  void send_frame(uint16_t opcode, uint8_t msg_type, const std::vector<uint8_t> &body, int seq_override = -1) {
    uint8_t seq = (seq_override >= 0) ? static_cast<uint8_t>(seq_override) : (++seq_num_);
    // Inner payload: [0x01, (opcode & 0xFF), (opcode >> 8), 0x00] + body
    std::vector<uint8_t> inner;
    inner.reserve(4 + body.size());
    inner.push_back(0x01);
    inner.push_back(static_cast<uint8_t>(opcode & 0xFF));
    inner.push_back(static_cast<uint8_t>((opcode >> 8) & 0xFF));
    inner.push_back(0x00);
    inner.insert(inner.end(), body.begin(), body.end());

    uint16_t len = static_cast<uint16_t>(inner.size());
    std::vector<uint8_t> packet;
    packet.reserve(6 + len);
    packet.push_back(0xA5);
    packet.push_back(msg_type);
    packet.push_back(seq);
    packet.push_back(static_cast<uint8_t>(len & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    packet.push_back(0x00); // Checksum placeholder
    packet.insert(packet.end(), inner.begin(), inner.end());

    // Calculate checksum: 0xFF ^ (sum(packet[0..5+len] except [5]) & 0xFF)
    uint32_t total = 0;
    for (size_t i = 0; i < packet.size(); ++i) {
      if (i != 5) total += packet[i];
    }
    packet[5] = static_cast<uint8_t>(0xFF ^ (total & 0xFF));

    if (send_raw_) {
      send_raw_(packet);
    }
  }

  SendUartFrameFn send_raw_;
  ProgressFn progress_cb_;
  CompletionFn completion_cb_;
  McuOtaState state_{McuOtaState::IDLE};
  const uint8_t *bin_data_{nullptr};
  size_t bin_size_{0};
  uint8_t ver_major_{1};
  uint8_t ver_minor_{0};
  uint8_t ver_patch_{0};
  uint16_t mtu_{512};
  uint8_t seq_num_{0};
};

}  // namespace levoit
}  // namespace esphome
