#pragma once

#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/components/update/update_entity.h"
#include "../levoit.h"

#ifdef USE_ESP_IDF
#include "esp_http_client.h"
#endif

namespace esphome {
namespace levoit {

class LevoitMcuUpdate : public update::UpdateEntity, public Component {
 public:
  LevoitMcuUpdate(Levoit *parent) : parent_(parent) {}

  void setup() override;
  void dump_config() override;

  void set_source_url(const std::string &url) { this->source_url_ = url; }
  void set_latest_version(const std::string &ver) {
    this->update_info_.latest_version = ver;
    this->check_update_state_();
  }

  void perform(bool force) override;
  void check() override;

  bool flash_binary(const uint8_t *data, size_t len, uint8_t v_maj = 1, uint8_t v_min = 0, uint8_t v_patch = 0);
  bool flash_from_url(const std::string &url);

 protected:
  Levoit *parent_{nullptr};
  std::string source_url_;
  std::vector<uint8_t> download_buffer_;

  void check_update_state_();
  bool download_firmware_(const std::string &url);
};

}  // namespace levoit
}  // namespace esphome
