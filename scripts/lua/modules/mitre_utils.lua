--
-- (C) 2013-24 - ntop.org
--

local dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

local alert_entities = require "alert_entities"

-- ##############################################

-- table containing information about mitre attack matrix
-- keep in sync with en.lua["mitre"] AND scripts/lua/modules/mitre_consts.lua

local mitre_utils = {
  tactic = {
      c_and_c = {
        id = 11,
        i18n_label = "mitre.tactic.c_and_c"
      },
      credential_access = {
        id = 6,
        i18n_label = "mitre.tactic.credential_access"
      },
      collection = {
        id = 9,
        i18n_label = "mitre.tactic.collection"
      },
      defense_evasion = {
        id = 5,
        i18n_label = "mitre.tactic.defense_evasion"
      },
      discovery = {
        id = 7,
        i18n_label = "mitre.tactic.discovery"
      },
      execution = {
        id = 2,
        i18n_label = "mitre.tactic.execution"
      },
      exfiltration = {
        id = 10,
        i18n_label = "mitre.tactic.exfiltration"
      },
      impact = {
        id = 40,
        i18n_label = "mitre.tactic.impact"},
      initial_access = {
        id = 1,
        i18n_label = "mitre.tactic.initial_access"
      },
      lateral_movement = {
        id = 8,
        i18n_label = "mitre.tactic.lateral_movement"
      },
      persistence = {
        id = 3,
        i18n_label = "mitre.tactic.persistence"
      },
      privilege_escalation = {
        id = 4,
        i18n_label = "mitre.tactic.privilege_escalation"
      },
      reconnaissance = {
        id = 43,
        i18n_label = "mitre.tactic.reconnaissance"},
      resource_develop = {
        id = 42,
        i18n_label = "mitre.tactic.resource_develop"
      },
   },
   -- Techniques
   technique = {
      account_manipulation = {
        id = 1098,
        i18n_label = "mitre.technique.account_manipulation"
      },
      active_scanning = {
        id = 1595,
        i18n_label = "mitre.technique.active_scanning"
      },
      adversary_in_the_middle = {
        id = 1557,
        i18n_label = "mitre.technique.adversary_in_the_middle"
      },
      app_layer_proto = {
        id = 1071,
        i18n_label = "mitre.technique.app_layer_proto"
      },
      automated_exf = {
        id = 1020,
        i18n_label = "mitre.technique.automated_exf"
      },
      content_inj = {
        id = 1659,
        i18n_label = "mitre.technique.content_inj"
      },
      data_destruction = {
        id = 1485,
        i18n_label = "mitre.technique.data_destruction"
      },
      data_from_conf_repo = {
        id = 1602,
        i18n_label = "mitre.technique.data_from_conf_repo"
      },
      data_from_net_shared_driver = {
        id = 1039,
        i18n_label = "mitre.technique.data_from_net_shared_driver"
      },
      data_manipulation = {
        id = 1565,
        i18n_label = "mitre.technique.data_manipulation"
      },
      data_obfuscation = {
        id = 1001,
        i18n_label = "mitre.technique.data_obfuscation"
      },
      drive_by_compr = {
        id = 1189,
        i18n_label = "mitre.technique.drive_by_compr"
      },
      dynamic_resolution = {
        id = 1568,
        i18n_label = "mitre.technique.dynamic_resolution"
      },
      encrypted_channel = {
        id = 1573,
        i18n_label = "mitre.technique.encrypted_channel"
      },
      endpoint_ddos = {
        id = 1499,
        i18n_label = "mitre.technique.endpoint_ddos"
      },
      exfiltration_over_alt_proto = {
        id = 1048,
        i18n_label = "mitre.technique.exfiltration_over_alt_proto"
      },
      exfiltration_over_c2_channel = {
        id = 1041,
        i18n_label = "mitre.technique.exfiltration_over_c2_channel"
      },
      exfiltration_over_web_service = {
        id = 1567,
        i18n_label = "mitre.technique.exfiltration_over_web_service"
      },
      exploitatation_client_exec = {
        id = 1203,
        i18n_label = "mitre.technique.exploitatation_client_exec"
      },
      expl_privilege_escalation = {
        id = 1068,
        i18n_label = "mitre.technique.expl_privilege_escalation"
      },
      exploit_pub_facing_app = {
        id = 1190,
        i18n_label = "mitre.technique.exploit_pub_facing_app"
      },
      ext_remote_services = {
        id = 1133,
        i18n_label = "mitre.technique.ext_remote_services"
      },
      forced_authentication = {
        id = 1187,
        i18n_label = "mitre.technique.forced_authentication"
      },
      gather_victim_net_info = {
        id = 1590,
        i18n_label = "mitre.technique.gather_victim_net_info"
      },
      hide_infrastructure = {
        id = 1665,
        i18n_label = "mitre.technique.hide_infrastructure"
      },
      impair_defenses = {
        id = 1562,
        i18n_label = "mitre.technique.impair_defenses"
      },
      indicator_removal = {
        id = 1070,
        i18n_label = "mitre.technique.indicator_removal"
      },
      ingress_tool_tranfer = {
        id = 1105,
        i18n_label = "mitre.technique.ingress_tool_tranfer"
      },
      internal_spearphishing = {
        id = 1534,
        i18n_label = "mitre.technique.internal_spearphishing"
      },
      lateral_tool_transfer = {
        id = 1570,
        i18n_label = "mitre.technique.lateral_tool_transfer"
      },
      network_ddos = {
        id = 1498,
        i18n_label = "mitre.technique.network_ddos"
      },
      network_service_discovery = {
        id = 1046,
        i18n_label = "mitre.technique.network_service_discovery"
      },
      network_sniffing = {
        id = 1040,
        i18n_label = "mitre.technique.Network Sniffing"
      },
      non_app_layer_proto = {
        id = 1095,
        i18n_label = "mitre.technique.non_app_layer_proto"
      },
      non_std_port = {
        id = 1571,
        i18n_label = "mitre.technique.non_std_port"
      },
      obfuscated_files_info = {
        id = 1027,
        i18n_label = "mitre.technique.obfuscated_files_info"
      },
      os_credential_dump = {
        id = 1003,
        i18n_label = "mitre.technique.os_credential_dump"
      },
      phishing = {
        id = 1566,
        i18n_label = "mitre.technique.phishing"
      },
      phishing_info = {
        id = 1598,
        i18n_label = "mitre.technique.phishing_info"
      },
      proxy = {
        id = 1090,
        i18n_label = "mitre.technique.proxy"
      },
      remote_services = {
        id = 1021,
        i18n_label = "mitre.technique.remote_services"
      },
      remote_system_discovery = {
        id = 1018,
        i18n_label = "mitre.technique.remote_system_discovery"
      },
      resource_hijacking = {
        id = 1496,
        i18n_label = "mitre.technique.resource_hijacking"
      },
      rogue_domain_controller = {
        id = 1207,
        i18n_label = "mitre.technique.rogue_domain_controller"
      },
      scheduled_tranfer = {
        id = 1029,
        i18n_label = "mitre.technique.scheduled_tranfer"
      },
      search_open_tech_db = {
        id = 1596,
        i18n_label = "mitre.technique.search_open_tech_db"
      },
      server_software_component = {
        id = 1505,
        i18n_label = "mitre.technique.server_software_component"
      },
      session_hijacking = {
        id = 1563,
        i18n_label = "mitre.technique.session_hijacking"
      },
      steal_web_session_cookie = {
        id = 1539,
        i18n_label = "mitre.technique.steal_web_session_cookie"
      },
      system_network_conf_discovery = {
        id = 1016,
        i18n_label = "mitre.technique.system_network_conf_discovery"
      },
      traffic_signaling = {
        id = 1205,
        i18n_label = "mitre.technique.traffic_signaling"
      },
      user_execution = {
        id = 1204,
        i18n_label = "mitre.technique.user_execution"
      },
      valid_accounts = {
        id = 1078,
        i18n_label = "mitre.technique.valid_accounts"
      },
      web_service = {
        id = 1102,
        i18n_label = "mitre.technique.web_service"
      },
   },
   -- Sub-Techniques
   sub_technique = {
      arp_cache_poisoning = {
        id = 155702,
        i18n_label = "mitre.sub_technique.sub_technique"
      },
      dhcp_spoofing = {
        id = 155703,
        i18n_label = "mitre.sub_technique.dhcp_spoofing"
      },
      direct_network_flood = {
        id = 149801,
        i18n_label = "mitre.sub_technique.direct_network_flood"
      },
      dns = {
        id = 107104,
        i18n_label = "mitre.sub_technique.dns"
      },
      dns_calculation = {
        id = 156803,
        i18n_label = "mitre.sub_technique.dns_calculation"
      },
      dns_passive_dns = {
        id = 159601,
        i18n_label = "mitre.sub_technique.dns_passive_dns"
      },
      domain_fronting = {
        id = 109004,
        i18n_label = "mitre.sub_technique.domain_fronting"
      },
      domain_generation_algorithms = {
        id = 156802,
        i18n_label = "mitre.sub_technique.domain_generation_algorithms"
      },
      external_proxy = {
        id = 109002,
        i18n_label = "mitre.sub_technique.external_proxy"
      },
      mail_protocol = {
        id = 107103,
        i18n_label = "mitre.sub_technique.mail_protocol"
      },
      malicious_link = {
        id = 120401,
        i18n_label = "mitre.sub_technique.malicious_link"
      },
      multi_hop_proxy = {
        id = 109003,
        i18n_label = "mitre.sub_technique.multi_hop_proxy"
      },
      network_device_config_dump = {
        id = 160202,
        i18n_label = "mitre.sub_technique.network_device_config_dump"
      },
      network_topology = {
        id = 159004,
        i18n_label = "mitre.sub_technique.network_topology"
      },
      one_way_communication = {
        id = 110203,
        i18n_label = "mitre.sub_technique.one_way_communication"
      },
      port_knocking = {
        id = 120501,
        i18n_label = "mitre.sub_technique.port_knocking"
      },
      protocol_impersonation = {
        id = 100103,
        i18n_label = "mitre.sub_technique.protocol_impersonation"
      },      
      rdp_hijacking = {
        id = 156302,
        i18n_label = "mitre.sub_technique.rdp_hijacking"
      },
      reflection_amplification = {
        id = 149802,
        i18n_label = "mitre.sub_technique.reflection_amplification"
      },
      remote_desktop_proto = {
        id = 102101,
        i18n_label = "mitre.sub_technique.remote_desktop_proto"
      },
      smb_relay = {
        id = 155701,
        i18n_label = "mitre.sub_technique.smb_relay"
      },
      smb_windows_admin_share = {
        id = 102102,
        i18n_label = "mitre.sub_technique.smb_windows_admin_share"
      },
      spearphishing_link = {
        id = 156602,
        i18n_label = "mitre.sub_technique.spearphishing_link"
      },
      spearphishing_service = {
        id = 156603,
        i18n_label = "mitre.sub_technique.spearphishing_service"
      },
      ssh = {
        id = 109804,
        i18n_label = "mitre.sub_technique.ssh"
      },
      web_protocol = {
        id = 107101,
        i18n_label = "mitre.sub_technique.web_protocol"
      },
      wordlist_scanning = {
        id = 159503,
        i18n_label = "mitre.sub_technique.wordlist_scanning"
      },
   }
}

-- ##############################################

mitre_utils.tactic_by_id = {}
mitre_utils.technique_by_id = {}
mitre_utils.sub_technique_by_id = {}

local function build_category_id_id_to_info()
   for tactic, info in pairs(mitre_utils.tactic) do
      mitre_utils.tactic_by_id[info.id] = info
   end

   for technique, info in pairs(mitre_utils.technique) do
      mitre_utils.technique_by_id[info.id] = info
   end

   for sub_technique, info in pairs(mitre_utils.sub_technique) do
      mitre_utils.sub_technique_by_id[info.id] = info
   end
end

build_category_id_id_to_info()

-- ##############################################

local mitre_id_to_categories = {}

--[[
  {
    MITRE_ID = {
      tactic = TACTIC_ID,
      technique = TECHNIQUE_ID,
      sub_technique = SUB_TECHNIQUE_ID
    },
    ...
  }
--]]

-- ##############################################

local function add_to_mitre_id_to_categories(mitre_info, alert_id, entity_id)
   if not mitre_info or not mitre_info.mitre_id then
      return
   end

   if not mitre_id_to_categories[mitre_info.mitre_id] then
      mitre_id_to_categories[mitre_info.mitre_id] = {
         alert_array = {}
      }
   end

   if not mitre_id_to_categories[mitre_info.mitre_id].tactic then
      mitre_id_to_categories[mitre_info.mitre_id].tactic = mitre_info.mitre_tactic_id
   end
   
   if not mitre_id_to_categories[mitre_info.mitre_id].technique then
      mitre_id_to_categories[mitre_info.mitre_id].technique = mitre_info.mitre_technique_id
   end

   if not mitre_id_to_categories[mitre_info.mitre_id].sub_technique then
      mitre_id_to_categories[mitre_info.mitre_id].sub_technique = mitre_info.mitre_sub_technique_id
   end

   mitre_id_to_categories[mitre_info.mitre_id].alert_array[#mitre_id_to_categories[mitre_info.mitre_id].alert_array + 1] =
      {alert_id, entity_id}
end

-- ##############################################

local function build_mitre_id_to_categories()
   local checks = require "checks"
   local alert_consts = require "alert_consts"

   local subdirs = {}

   for _, subdir in pairs(checks.listSubdirs()) do
      subdirs[#subdirs + 1] = subdir.id
   end

   for _, subdir in ipairs(subdirs) do
      local script_type = checks.getScriptType(subdir)
      local scripts = checks.load(getSystemInterfaceId(), script_type, subdir, {return_all = false})

      for script_name, script in pairs(scripts.modules) do
	 if alert_entities[subdir] then
	    local entity_id = alert_entities[subdir].entity_id

	    if entity_id ~= nil then
	       local alert_key = alert_consts.getAlertType(script.alert_id, entity_id)

	       if alert_key ~= nil then
		  local mitre_info = alert_consts.getAlertMitreInfoIDs(alert_key)
		  add_to_mitre_id_to_categories(mitre_info, script.alert_id, entity_id)
	       end
            end
	 end
      end
   end

   return mitre_id_to_categories
end

-- ##############################################

function mitre_utils.insertDBMitreInfo()
   local value_to_add = ""
   local table_name = "mitre_table_info"
   local table_name_with_values = string.format("%s (alert_id, entity_id, tactic, technique, sub_technique, mitre_id)", table_name)

   build_mitre_id_to_categories()

   for mitre_id, value in pairs(mitre_id_to_categories) do
      local current_values = ""
      for _, alert_key in pairs(value.alert_array) do
	 if value.tactic == nil then
	    value.tactic = 0
	 end
	 if value.technique == nil then
	    value.technique = 0
	 end
	 if value.sub_technique == nil then
	    value.sub_technique = 0
	 end
	 current_values = current_values.."("..alert_key[1]..","..alert_key[2]..","..value.tactic..","..value.technique
	    ..","..value.sub_technique..",'"..mitre_id.."'),"
      end
      value_to_add = value_to_add .. current_values
   end

   -- replace the last ',' character with ';' in order to push all value in one into the DB
   value_to_add = value_to_add:sub(1, -2)..";"
   local sql
   if hasClickHouseSupport() then
      table_name_with_values = "mitre_table_info (ALERT_ID, ENTITY_ID, TACTIC, TECHNIQUE, SUB_TECHNIQUE, MITRE_ID)"
      sql = "INSERT INTO "..table_name_with_values.." VALUES "..value_to_add
      interface.alert_store_query(sql)
      interface.alert_store_query("OPTIMIZE TABLE ".. table_name .. " FINAL;")
   end
end

-- ##############################################

return mitre_utils
