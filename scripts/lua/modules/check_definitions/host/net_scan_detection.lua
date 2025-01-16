--
-- (C) 2019-24 - ntop.org
--

local checks = require("checks")
local host_alert_keys = require "host_alert_keys"
local alert_consts = require("alert_consts")

local script = {
  -- Script category
  category = checks.check_categories.security,
  
  -- This module is disabled by default
  default_enabled = false,

  alert_id = host_alert_keys.host_alert_net_scan_detected,
  severity = alert_consts.get_printable_severities().error,
  
  default_value = {
    incomplete_flows = {
        default_value = 32,
        field_min = 1,
        field_max = 65535,
        field_operator = "gt",
        i18n_fields_unit = checks.field_units.flows,
        i18n_title = 'incomplete_flows'
    },
    contacts_as_client = {
        default_value = 8,
        field_min = 1,
        field_max = 65535,
        field_operator = "gt",
        i18n_fields_unit = checks.field_units.flows,
        i18n_title = 'contacts_as_client'
    },
  },

  -- See below
  hooks = {},

  -- Allow user script configuration from the GUI
  gui = {
    i18n_title = "entity_thresholds.net_scan_detection_title",
    i18n_description = "entity_thresholds.net_scan_detection_description",
    input_builder = "threshold_cross",
  }
}

-- #################################################################

return script
