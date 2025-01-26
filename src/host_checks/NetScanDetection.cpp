/*
 *
 * (C) 2013-24 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "ntop_includes.h"
#include "host_checks_includes.h"

/* ***************************************************** */

NetScanDetection::NetScanDetection()
    : HostCheck(ntopng_edition_community, false /* All interfaces */,
                false /* Don't exclude for nEdge */,
                false /* NOT only for nEdge */) {
  num_contacts_as_cli_treshold = (u_int32_t)30;
};

/* ***************************************************** */

void NetScanDetection::periodicUpdate(Host *h, HostAlert *engaged_alert) {
  HostAlert *alert = engaged_alert;
  u_int32_t cli_contacts = h->getNetScanDetectorContacts();

  if (cli_contacts > num_contacts_as_cli_treshold) {
    if (!alert)
      alert = allocAlert(this, h, CLIENT_FULL_RISK_PERCENTAGE, cli_contacts, num_contacts_as_cli_treshold);
    if (alert) {
      h->triggerAlert(alert);
      h->resetNetScanDetectorContacts();
    }
  }
  
}

/* ***************************************************** */

bool NetScanDetection::loadConfiguration(json_object *config) {
  json_object *json_table, *json_threshold;

  HostCheck::loadConfiguration(config); /* Parse parameters in common */
  
  if (json_object_object_get_ex(config, "threshold", &json_threshold))
      num_contacts_as_cli_treshold = json_object_get_int64(json_threshold);
      
  return (true);
}

/* ***************************************************** */
