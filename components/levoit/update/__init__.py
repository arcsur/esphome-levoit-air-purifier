from esphome.components import update
import esphome.config_validation as cv
import esphome.codegen as cg
from esphome.const import (
    CONF_ID,
    DEVICE_CLASS_FIRMWARE,
    ENTITY_CATEGORY_CONFIG,
)
from .. import levoit_ns, CONF_LEVOIT_ID, Levoit

DEPENDENCIES = ["levoit"]
CODEOWNERS = ["@arcsur", "@acvigue"]

LevoitMcuUpdate = levoit_ns.class_("LevoitMcuUpdate", update.UpdateEntity, cg.Component)

CONF_SOURCE_URL = "source_url"
CONF_LATEST_VERSION = "latest_version"

CONFIG_SCHEMA = (
    update.update_schema(
        LevoitMcuUpdate,
        device_class=DEVICE_CLASS_FIRMWARE,
        entity_category=ENTITY_CATEGORY_CONFIG,
        icon="mdi:chip",
    )
    .extend(
        {
            cv.GenerateID(CONF_LEVOIT_ID): cv.use_id(Levoit),
            cv.Optional(CONF_SOURCE_URL): cv.string,
            cv.Optional(CONF_LATEST_VERSION): cv.string,
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
)

async def to_code(config):
    parent = await cg.get_variable(config[CONF_LEVOIT_ID])
    var = cg.new_Pvariable(config[CONF_ID], parent)
    await cg.register_component(var, config)
    await update.register_update(var, config)

    if source_url := config.get(CONF_SOURCE_URL):
        cg.add(var.set_source_url(source_url))
    if latest_version := config.get(CONF_LATEST_VERSION):
        cg.add(var.set_latest_version(latest_version))
