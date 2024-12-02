--
-- (C) 2021-24 - ntop.org
--

local dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/alert_store/?.lua;" .. package.path

-- Import the classes library.
local classes = require "classes"

require "lua_utils"
local alert_store = require "alert_store"
local format_utils = require "format_utils"
local alert_consts = require "alert_consts"
local alert_utils = require "alert_utils"
local alert_entities = require "alert_entities"
local discover = require "discover_utils"
local json = require "dkjson"

-- ##############################################

local mac_alert_store = classes.class(alert_store)

-- ##############################################

function mac_alert_store:init(args)
   self.super:init()

   if ntop.isClickHouseEnabled() then
      self._table_name = "mac_alerts_view"
      self._write_table_name = "mac_alerts"
      self._engaged_write_table_name = "engaged_mac_alerts"
   else
      self._table_name = "mac_alerts_view"
      self._write_table_name = "mac_alerts"
      self._engaged_write_table_name = "mem_db.engaged_mac_alerts"
   end

   self._alert_entity = alert_entities.mac
end

-- ##############################################

function mac_alert_store:_build_insert_query(alert, write_table, alert_status, extra_columns, extra_values)
   local insert_stmt = string.format("INSERT INTO %s " ..
      "(%salert_id, alert_status, require_attention, interface_id, tstamp, tstamp_end, severity, score, address, device_type, name, " ..
      "is_attacker, is_victim, json) " ..
      "VALUES (%s%u, %u, %u, %d, %u, %u, %u, %u, '%s', %u, '%s', %u, %u, '%s'); ",
      write_table,
      extra_columns,
      extra_values,
      alert.alert_id,
      alert_status,
      ternary(alert.require_attention, 1, 0),
      self:_convert_ifid(interface.getId()),
      alert.tstamp,
      alert.tstamp_end,
      map_score_to_severity(alert.score),
      alert.score,
      self:_escape(alert.entity_val),
      alert.device_type or 0,
      self:_escape(alert.device_name),
      ternary(alert.is_attacker, 1, 0),
      ternary(alert.is_victim, 1, 0),
      self:_escape(alert.json))

   return insert_stmt
end

-- ##############################################

--@brief Performs a query for the top device address by alert count
function mac_alert_store:top_address_historical()
   -- Preserve all the filters currently set
   local where_clause = self:build_where_clause()

   local q = string.format(
      "SELECT address, count(*) count FROM %s WHERE %s GROUP BY address ORDER BY count DESC LIMIT %u",
      self._table_name, where_clause, self._top_limit)

   local q_res = interface.alert_store_query(q) or {}

   return q_res
end

-- ##############################################

--@brief Stats used by the dashboard
function mac_alert_store:_get_additional_stats()
   local stats = {}
   stats.top = {}
   stats.top.address = self:top_address_historical()
   return stats
end

-- ##############################################

-- @brief Get info about additional available filters
function mac_alert_store:_get_additional_available_filters()
   local tag_utils = require "tag_utils"
   local filters = {
      mac = tag_utils.defined_tags.mac,
   }

   return filters
end

-- ##############################################

--@brief Add filters according to what is specified inside the REST API
function mac_alert_store:_add_additional_request_filters()
   -- Add filters specific to the mac family
   local mac = _GET["mac"]
   self:add_filter_condition_list('address', mac)
end

-- ##############################################

local RNAME = {
   ADDRESS = { name = "address", export = true },
   DEVICE_TYPE = { name = "device_type", export = true },
   NAME = { name = "name", export = true },
   DESCRIPTION = { name = "description", export = true },
   MSG = { name = "msg", export = true, elements = { "name", "value", "description" } }
}

function mac_alert_store:get_rnames()
   return RNAME
end

--@brief Convert an alert coming from the DB (value) to a record returned by the REST API
function mac_alert_store:format_record(value, no_html)
   local record = self:format_json_record_common(value, alert_entities.mac.entity_id, no_html)

   local alert_info = alert_utils.getAlertInfo(value)
   local alert_name = alert_consts.alertTypeLabel(tonumber(value["alert_id"]), no_html, alert_entities.mac.entity_id)
   local alert_fullname = alert_consts.alertTypeLabel(tonumber(value["alert_id"]), true, alert_entities.mac.entity_id)
   local msg = alert_utils.formatAlertMessage(ifid, value, alert_info)

   record[RNAME.ADDRESS.name] = {
      value = value["address"],
      label = value["address"]
   }
   
   record[RNAME.DEVICE_TYPE.name] = {
      value = value["device_type"],
      label = string.format("%s %s", discover.devtype2string(value["device_type"]),
         discover.devtype2icon(value["device_type"])),
   }

   record[RNAME.NAME.name] = value["name"]

   if string.lower(noHtml(msg)) == string.lower(noHtml(alert_name)) then
      msg = ""
   end

   if no_html then
      msg = noHtml(msg)
   end

   record[RNAME.DESCRIPTION.name] = msg

   record[RNAME.MSG.name] = {
      name = noHtml(alert_name),
      fullname = alert_fullname,
      value = tonumber(value["alert_id"]),
      description = msg,
      configset_ref = alert_utils.getConfigsetAlertLink(alert_info)
   }

   return record
end

-- ##############################################

return mac_alert_store
