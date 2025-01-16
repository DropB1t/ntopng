--
-- (C) 2019-24 - ntop.org
--

-- ##############################################

local host_alert_keys = require "host_alert_keys"

local json = require("dkjson")
local alert_creators = require "alert_creators"
-- Import the classes library.
local classes = require "classes"
-- Make sure to import the Superclass!
local alert = require "alert"
-- Import Mitre Att&ck utils
local mitre = require "mitre_utils"

-- ##############################################

local host_alert_net_scan_detected = classes.class(alert)

-- ##############################################

host_alert_net_scan_detected.meta = {
  alert_key = host_alert_keys.host_alert_net_scan_detected, -- host_alert_keys.lua
  i18n_title = "alerts_dashboard.net_scan_detected",
  icon = "fas fa-fw fa-life-ring",
  has_attacker = true,

  -- Mitre Att&ck Matrix values
  mitre_values = {
    mitre_tactic = mitre.tactic.reconnaissance,
    mitre_technique = mitre.technique.active_scanning,
    mitre_id = "T1595"
  },
}

-- ##############################################

function host_alert_net_scan_detected:init()
    -- Call the parent constructor
    self.super:init()
 end
 
 -- #######################################################

-- @brief Format an alert into a human-readable string
-- @param ifid The integer interface id of the generated alert
-- @param alert The alert description table, including alert data such as the generating entity, timestamp, granularity, type
-- @param alert_type_params Table `alert_type_params` as built in the `:init` method
-- @return A human-readable string
function host_alert_net_scan_detected.format(ifid, alert, alert_type_params)
    -- TODO - Implement the alert formated message
    return "Network scan detected"
 end
 
 -- #######################################################
 
 return host_alert_net_scan_detected