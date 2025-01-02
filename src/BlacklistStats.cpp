/*
 *
 * (C) 2019-25 - ntop.org
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

/* *************************************************** */

void BlacklistStats::incHits(std::string name) {
  std::unordered_map<std::string, BlacklistUsageStats>::iterator it;

   /*
     Necessary as the core can increase the number of hits
     while lua can read values
   */
  lock.wrlock(__FILE__, __LINE__);
  
  it = stats.find(name);

  if (it == stats.end()) {
    BlacklistUsageStats l;

    stats[name] = l;
#if 0
  ntop->getTrace()->traceEvent(TRACE_NORMAL,
                                "Blacklist %s contacted [hits=%u]",
                                name, stats[name]);
#endif
  } else {
    it->second.incHits();
    
#if 0
  ntop->getTrace()->traceEvent(TRACE_NORMAL,
                                "Blacklist %s contacted [hits=%u]",
                                name, it->second.getNumHits());
#endif
  }
  
  
  lock.unlock(__FILE__, __LINE__);
}

/* *************************************************** */

u_int32_t BlacklistStats::getNumHits(std::string name) {
  std::unordered_map<std::string, BlacklistUsageStats>::iterator it;
  u_int32_t ret;
  
  lock.rdlock(__FILE__, __LINE__);
  
  it = stats.find(name);

  if (it == stats.end())
    ret = 0;
  else
    ret = it->second.getNumHits();

  lock.unlock(__FILE__, __LINE__);

  return(ret);
}

/* *************************************************** */

void BlacklistStats::lua(lua_State* vm) {
  lua_newtable(vm);

  lock.rdlock(__FILE__, __LINE__);

  for(std::unordered_map<std::string, BlacklistUsageStats>::iterator it = stats.begin(); it != stats.end(); ++it) {
    lua_newtable(vm);
    lua_push_int32_table_entry(vm, "total", it->second.getNumTotalHits());
    lua_push_int32_table_entry(vm, "current", it->second.getNumHits());
    lua_pushstring(vm, it->first.c_str());
    lua_insert(vm, -2);
    lua_settable(vm, -3);

  }
  
  lock.unlock(__FILE__, __LINE__);
}

/* *************************************************** */

void BlacklistStats::reset() {
  lock.wrlock(__FILE__, __LINE__);

  for(std::unordered_map<std::string, BlacklistUsageStats>::iterator it = stats.begin(); it != stats.end(); ++it)
    it->second.resetNumHits();  
    
  lock.unlock(__FILE__, __LINE__);
}
