#include "levoit_mcu_update.h"
#include "esphome/core/log.h"
#include <cstdio>

namespace esphome {
namespace levoit {

static const char *const TAG = "levoit.update";

void LevoitMcuUpdate::setup() {
  if (this->update_info_.title.empty()) {
    this->update_info_.title = "Main MCU Firmware";
  }
  this->update_info_.current_version = this->parent_->get_mcu_version();

  this->parent_->set_mcu_version_listener([this](const std::string &ver) {
    this->update_info_.current_version = ver;
    this->check_update_state_();
    this->publish_state();
  });

  this->parent_->set_mcu_ota_progress_callback([this](size_t written, size_t total, float pct) {
    this->update_info_.has_progress = true;
    this->update_info_.progress = pct;
    this->publish_state();
  });

  this->parent_->set_mcu_ota_completion_callback([this](bool success, const char *msg) {
    this->update_info_.has_progress = false;
    if (success) {
      ESP_LOGI(TAG, "MCU Firmware Update Succeeded: %s", msg);
      if (!this->update_info_.latest_version.empty()) {
        this->update_info_.current_version = this->update_info_.latest_version;
      }
      this->state_ = update::UPDATE_STATE_NO_UPDATE;
    } else {
      ESP_LOGE(TAG, "MCU Firmware Update Failed: %s", msg);
      this->state_ = update::UPDATE_STATE_AVAILABLE;
    }
    this->publish_state();
  });

  this->check_update_state_();
  this->publish_state();
}

void LevoitMcuUpdate::dump_config() {
  ESP_LOGCONFIG(TAG, "Levoit MCU Update Entity:");
  ESP_LOGCONFIG(TAG, "  Current Version: %s", this->update_info_.current_version.c_str());
  ESP_LOGCONFIG(TAG, "  Latest Version: %s", this->update_info_.latest_version.c_str());
  ESP_LOGCONFIG(TAG, "  Source URL: %s", this->source_url_.c_str());
}

void LevoitMcuUpdate::check_update_state_() {
  if (this->update_info_.current_version == "Unknown" || this->update_info_.latest_version.empty()) {
    this->state_ = update::UPDATE_STATE_UNKNOWN;
  } else if (this->update_info_.current_version != this->update_info_.latest_version) {
    this->state_ = update::UPDATE_STATE_AVAILABLE;
  } else {
    this->state_ = update::UPDATE_STATE_NO_UPDATE;
  }
}

void LevoitMcuUpdate::check() {
  ESP_LOGI(TAG, "Checking for MCU firmware updates...");
  this->check_update_state_();
  this->publish_state();
}

void LevoitMcuUpdate::perform(bool force) {
  if (this->source_url_.empty()) {
    ESP_LOGE(TAG, "Cannot perform update: No source_url configured");
    return;
  }
  ESP_LOGI(TAG, "Starting MCU firmware update from %s...", this->source_url_.c_str());
  this->state_ = update::UPDATE_STATE_INSTALLING;
  this->update_info_.has_progress = true;
  this->update_info_.progress = 0.0f;
  this->publish_state();

  this->flash_from_url(this->source_url_);
}

bool LevoitMcuUpdate::flash_binary(const uint8_t *data, size_t len, uint8_t v_maj, uint8_t v_min, uint8_t v_patch) {
  if (!this->parent_) return false;
  this->state_ = update::UPDATE_STATE_INSTALLING;
  this->update_info_.has_progress = true;
  this->update_info_.progress = 0.0f;
  this->publish_state();

  return this->parent_->start_mcu_ota(data, len, v_maj, v_min, v_patch);
}

bool LevoitMcuUpdate::flash_from_url(const std::string &url) {
  if (!this->download_firmware_(url)) {
    ESP_LOGE(TAG, "Failed to download MCU firmware binary");
    this->state_ = update::UPDATE_STATE_AVAILABLE;
    this->update_info_.has_progress = false;
    this->publish_state();
    return false;
  }

  uint8_t maj = 1, min = 0, patch = 0;
  if (!this->update_info_.latest_version.empty()) {
    int parsed_maj = 1, parsed_min = 0, parsed_patch = 0;
    if (std::sscanf(this->update_info_.latest_version.c_str(), "%d.%d.%d", &parsed_maj, &parsed_min, &parsed_patch) >= 1) {
      maj = static_cast<uint8_t>(parsed_maj);
      min = static_cast<uint8_t>(parsed_min);
      patch = static_cast<uint8_t>(parsed_patch);
    }
  }

  return this->flash_binary(this->download_buffer_.data(), this->download_buffer_.size(), maj, min, patch);
}

bool LevoitMcuUpdate::download_firmware_(const std::string &url) {
  this->download_buffer_.clear();

#ifdef USE_ESP_IDF
  esp_http_client_config_t config = {};
  config.url = url.c_str();
  config.timeout_ms = 10000;
  config.skip_cert_common_name_check = true;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    ESP_LOGE(TAG, "Failed to initialize HTTP client");
    return false;
  }

  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }

  int content_length = esp_http_client_fetch_headers(client);
  int status_code = esp_http_client_get_status_code(client);
  if (status_code != 200) {
    ESP_LOGE(TAG, "HTTP server returned error %d", status_code);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  if (content_length > 65536) {
    ESP_LOGE(TAG, "Firmware binary too large (%d bytes, max 64KB)", content_length);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  this->download_buffer_.reserve(content_length > 0 ? content_length : 16384);
  char buffer[512];
  int read_bytes = 0;
  while ((read_bytes = esp_http_client_read(client, buffer, sizeof(buffer))) > 0) {
    this->download_buffer_.insert(this->download_buffer_.end(), buffer, buffer + read_bytes);
    if (this->download_buffer_.size() > 65536) {
      ESP_LOGE(TAG, "Firmware size exceeded 64KB limit");
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    }
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  ESP_LOGI(TAG, "Successfully downloaded %zu bytes of MCU firmware", this->download_buffer_.size());
  return !this->download_buffer_.empty();
#else
  ESP_LOGE(TAG, "HTTP client not supported in this framework");
  return false;
#endif
}

}  // namespace levoit
}  // namespace esphome
