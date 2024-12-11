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

#ifndef _IEC_INVALID_COMMAND_TRANSITION_ALERT_H_
#define _IEC_INVALID_COMMAND_TRANSITION_ALERT_H_

#include "ntop_includes.h"

class IECInvalidCommandTransitionAlert : public FlowAlert {
 private:
  u_int32_t packet_epoch;
  u_int32_t transitions_m_to_c, transitions_c_to_m, transitions_c_to_c;

  ndpi_serializer *getAlertJSON(ndpi_serializer *serializer);

 public:
  static FlowAlertType getClassType() {
    return {flow_alert_iec_invalid_command_transition, alert_category_security};
  }
  static u_int8_t getDefaultScore() { return SCORE_LEVEL_NOTICE; };

  inline u_int32_t get_packet_epoch() { return packet_epoch; };
  inline u_int32_t get_transitions_m_to_c() { return transitions_m_to_c; };
  inline u_int32_t get_transitions_c_to_m() { return transitions_c_to_m; };
  inline u_int32_t get_transitions_c_to_c() { return transitions_c_to_c; };

  IECInvalidCommandTransitionAlert(FlowCheck *c, Flow *f, struct timeval *_time,
                                   u_int32_t _transitions_m_to_c,
                                   u_int32_t _transitions_c_to_m,
                                   u_int32_t _transitions_c_to_c)
      : FlowAlert(c, f) {
    transitions_m_to_c = _transitions_m_to_c;
    transitions_c_to_m = _transitions_c_to_m;
    transitions_c_to_c = _transitions_c_to_c;
    packet_epoch = _time->tv_sec;
    setAlertScore(getDefaultScore());
  };
  ~IECInvalidCommandTransitionAlert(){};

  bool autoAck() const { return false; };

  FlowAlertType getAlertType() const { return getClassType(); }
};

#endif /* _IEC_INVALID_COMMAND_TRANSITION_ALERT_H_ */
