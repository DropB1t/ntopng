--
-- (C) 2019-21 - ntop.org
--

-- ##############################################

local flow_alert_keys = require "flow_alert_keys"
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path
-- Import the classes library.
local classes = require "classes"
-- Make sure to import the Superclass!
local alert = require "alert"

-- ##############################################

local alert_ndpi_tls_not_carrying_https = classes.class(alert)

-- ##############################################

alert_ndpi_tls_not_carrying_https.meta = {
   alert_key  = flow_alert_keys.flow_alert_ndpi_tls_not_carrying_https,
   i18n_title = "alerts_dashboard.ndpi_tls_not_carrying_https_title",
   icon = "fas fa-fw fa-exclamation",
}

-- ##############################################

-- @brief Prepare an alert table used to generate the alert
-- @return A table with the alert built
function alert_ndpi_tls_not_carrying_https:init()
   -- Call the parent constructor
   self.super:init()
end

-- #######################################################

function alert_ndpi_tls_not_carrying_https.format(ifid, alert, alert_type_params)
   return
end

-- #######################################################

return alert_ndpi_tls_not_carrying_https
