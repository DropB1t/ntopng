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
#include "flow_checks_includes.h"

void ExternalAlertCheck::checkExternalAlert(Flow *f) {
  if (f->hasExternalAlert()) {
    FlowAlertType alert_type = ExternalAlertCheckAlert::getClassType();
    risk_percentage cli_score_pctg = CLIENT_FAIR_RISK_PERCENTAGE;
    u_int8_t c_score, s_score;

    computeCliSrvScore(ntop->getFlowAlertScore(alert_type.id), cli_score_pctg, &c_score, &s_score);

    FlowAlert *alert = buildAlert(f);
    f->triggerAlert(alert, c_score, s_score);
  }
}

/* ***************************************************** */

void ExternalAlertCheck::protocolDetected(Flow *f) { checkExternalAlert(f); }

/* ***************************************************** */

void ExternalAlertCheck::flowEnd(Flow *f) { checkExternalAlert(f); }

/* ***************************************************** */

FlowAlert *ExternalAlertCheck::buildAlert(Flow *f) {
  return new ExternalAlertCheckAlert(this, f);
}

/* ***************************************************** */
