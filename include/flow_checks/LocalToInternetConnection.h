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

#ifndef _LOCAL_TO_INTERNET_CONNECTION_H_
#define _LOCAL_TO_INTERNET_CONNECTION_H_

#include "ntop_includes.h"

class LocalToInternetConnection : public FlowCheck {
 public:
  LocalToInternetConnection()
      : FlowCheck(ntopng_edition_community, true /* Packet Interfaces only */,
                  true /* Exclude for nEdge */, false /* Only for nEdge */,
                  true /* has_protocol_detected */,
                  false /* has_periodic_update */, false /* has_flow_end */){};
  virtual ~LocalToInternetConnection(){};

  void protocolDetected(Flow *f);
  FlowAlert *buildAlert(Flow *f);

  std::string getName() const { return (std::string("local_to_internet_connection")); }
};

#endif /* _LOCAL_TO_INTERNET_CONNECTION_H_ */
