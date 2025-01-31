/*
 *
 * (C) 2017-25 - ntop.org
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

#ifndef _QUEUED_THREAD_DATA_
#define _QUEUED_THREAD_DATA_

#include "ntop_includes.h"

class QueuedThreadData {
 public:
  ThreadedActivity *j;
  char *script_path;
  NetworkInterface *iface;
  bool adaptive_pool_size;
  time_t deadline;
  PeriodicActivities *pa;
  bool hourly_daily_activity;
  
  QueuedThreadData(ThreadedActivity *_j, char *_path, NetworkInterface *_iface,
                   time_t _deadline, PeriodicActivities *_pa,
		   bool _hourly_daily_activity);

  ~QueuedThreadData();

  void run();
};


#endif /* _QUEUED_THREAD_DATA_ */
