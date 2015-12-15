/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : service.h
 * Author            : Push Chen
 * Date              : 2015-11-21
*/

/*
    LGPL V3 Lisence
    This file is part of cleandns.

    cleandns is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    cleandns is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with cleandns.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
    LISENCE FOR CLEANDNS
    COPYRIGHT (c) 2014, Push Chen.
    ALL RIGHTS RESERVED.

    REDISTRIBUTION AND USE IN SOURCE AND BINARY
    FORMS, WITH OR WITHOUT MODIFICATION, ARE
    PERMITTED PROVIDED THAT THE FOLLOWING CONDITIONS
    ARE MET:

    YOU USE IT, AND YOU JUST USE IT!.
    WHY NOT USE THIS LIBRARY IN YOUR CODE TO MAKE
    THE DEVELOPMENT HAPPIER!
    ENJOY YOUR LIFE AND BE FAR AWAY FROM BUGS.
*/

#pragma once

#ifndef __CLEAN_DNS_SERVICE_H__
#define __CLEAN_DNS_SERVICE_H__

#include "base64.h"
#include "socketlite.h"
#include "filter.h"

#include "json/json.h"
#include "json/json-forwards.h"

#include <list>
#include <algorithm>
#include <unordered_map>

class clnd_config_service {
protected:
    unordered_map<uint32_t, bool>   a_records_cache_;
    mutex                           a_records_mutex_;
    clnd_protocol_t                 service_protocol_;
    uint16_t                        port_;
    string                          logpath_;
    cp_log_level                    loglv_;
    bool                            daemon_;
    string                          pidfile_;
    uint16_t                        control_port_;
    bool                            gateway_;
    uint16_t                        gateway_port_;
    sl_peerinfo                     gateway_socks5_;

    cp_log_level _loglv_from_string(const string& loglv_string);
public:

    // const reference
    unordered_map<uint32_t, bool>&  a_records_cache;
    const clnd_protocol_t &         service_protocol;
    const uint16_t &                port;
    const string &                  logpath;
    const cp_log_level &            loglv;
    const bool &                    daemon;
    const string &                  pidfile;
    const uint16_t &                control_port;
    const bool &                    gateway;
    const uint16_t &                gateway_port;
    const sl_peerinfo &             gateway_socks5;

    clnd_config_service( );
    virtual ~clnd_config_service();

    clnd_config_service( const Json::Value& config_node );

    void start_log() const;

    // Local Gateway Black List cache
    void add_a_record_cache(uint32_t ipaddr);
    bool is_ip_in_a_record_cache(uint32_t ipaddr);
};

// Output the main help document
void cleandns_help();
// Output the filter's help document
void cleandns_filterhelp();
// Output the version info
void cleandns_version_info();

typedef shared_ptr<clnd_config_service> service_t;
extern service_t _g_service_config;

// Load the service config
bool load_service_config_from_file(const string &config_path);

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
