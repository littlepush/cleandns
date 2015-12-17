/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : service.cpp
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

#include "service.h"
#include "json-utility.h"

#ifdef CLRD_AUTO_GENERATE_DOC
#include "doc_header_auto_generate.h"
#endif

cp_log_level clnd_config_service::_loglv_from_string(const string& loglv_string) {
    string _lowercase = loglv_string;
    std::transform(_lowercase.begin(), _lowercase.end(), _lowercase.begin(), ::tolower);
    cp_log_level _lv = log_info;    // default is info
    if ( loglv_string == "emergancy" ) {
        _lv = log_emergancy;
    } else if ( loglv_string == "alert" ) {
        _lv = log_alert;
    } else if ( loglv_string == "critical" ) {
        _lv = log_critical;
    } else if ( loglv_string == "error" ) {
        _lv = log_error;
    } else if ( loglv_string == "warning" ) {
        _lv = log_warning;
    } else if ( loglv_string == "notice" ) {
        _lv = log_notice;
    } else if ( loglv_string == "info" ) {
        _lv = log_info;
    } else if ( loglv_string == "debug" ) {
        _lv = log_debug;
    }
    return _lv;
}
clnd_config_service::clnd_config_service( ) :
    a_records_cache(a_records_cache_),
    service_protocol(service_protocol_),
    port(port_),
    logpath(logpath_),
    loglv(loglv_),
    daemon(daemon_),
    pidfile(pidfile_), 
    control_port(control_port_),
    gateway(gateway_),
    gateway_port(gateway_port_),
    gateway_socks5(gateway_socks5_),
    gateway_access_control(gateway_access_control_)
    { /* nothing */ }
clnd_config_service::~clnd_config_service() { /* nothing */ }

clnd_config_service::clnd_config_service( const Json::Value& config_node ) :
    a_records_cache(a_records_cache_),
    service_protocol(service_protocol_),
    port(port_),
    logpath(logpath_),
    loglv(loglv_),
    daemon(daemon_),
    pidfile(pidfile_),
    control_port(control_port_),
    gateway(gateway_),
    gateway_port(gateway_port_),
    gateway_socks5(gateway_socks5_),
    gateway_access_control(gateway_access_control_)
{
    // Service
    service_protocol_ = clnd_protocol_from_string(
        check_key_with_default(config_node, "protocol", "all").asString());
    port_ = check_key_with_default(config_node, "port", 53).asUInt();
    logpath_ = check_key_with_default(config_node, "logpath", "syslog").asString();
    loglv_ = _loglv_from_string(
        check_key_with_default(config_node, "loglv", "info").asString()
        );
    daemon_ = check_key_with_default(config_node, "daemon", true).asBool();
    pidfile_ = check_key_with_default(config_node, "pidfile", "/var/run/cleandns/pid").asString();
    control_port_ = check_key_with_default(config_node, "control_port", 1053).asUInt();
    gateway_ = check_key_with_default(config_node, "gateway", false).asBool();
    gateway_port_ = check_key_with_default(config_node, "gateway_port", 4300).asUInt();
    gateway_socks5_ = check_key_with_default(config_node, "gateway_socks5", "0.0.0.0:0").asString();
    if ( config_node.isMember("access_control") ) {
        check_key_mustbe_array(config_node, "access_control");
        Json::Value _aclist = config_node["access_control"];
        for ( Json::ArrayIndex i = 0; i < _aclist.size(); ++i ) {
            sl_iprange _range(_aclist[i].asString());
            if ( _range ) {
                gateway_access_control_.emplace_back(_range);
            } else {
                lwarning << "the config of access control is not validate " << _aclist[i].asString() << lend;
            }
        }
    }
}

void clnd_config_service::start_log() const {
    // Stop the existed log
    // cp_log_stop();
    // Check system log path
    if ( logpath_ == "syslog" ) {
        log_arguments::instance().start(loglv_, "cleandns");
    } else if ( logpath_ == "stdout" ) {
        log_arguments::instance().start(stdout, loglv_);
    } else if ( logpath_ == "stderr" ) {
        log_arguments::instance().start(stderr, loglv_);
    } else {
        log_arguments::instance().start(logpath_, loglv_);
    }
}
void clnd_config_service::add_a_record_cache(uint32_t ipaddr)
{
    lock_guard<mutex> _(a_records_mutex_);
    a_records_cache_[ipaddr] = true;
}
bool clnd_config_service::is_ip_in_a_record_cache(uint32_t ipaddr)
{
    lock_guard<mutex> _(a_records_mutex_);
    return a_records_cache_.find(ipaddr) != end(a_records_cache_);
}
bool clnd_config_service::allow_access_from_ip(const sl_ip& in_ip)
{
    if ( gateway_access_control_.size() == 0 ) return true;
    for ( auto & _range : gateway_access_control_ ) {
        if ( _range.is_ip_in_range(in_ip) ) return true;
    }
    return false;
}


#ifdef CLRD_AUTO_GENERATE_DOC
#include "doc_header_auto_generate.h"
#endif

void cleandns_help() {
#if CLRD_AUTO_GENERATE_DOC
    static const string _helpDoc = CLEANDNS_DOC_HELP;
    string _helpString;
    base64_decode(_helpDoc, _helpString);
    cout << _helpString << endl;
#else
    cout << "Please visit <https://github.com/littlepush/cleandns> for usage." << endl;
#endif
}

void cleandns_filterhelp() {
#if CLRD_AUTO_GENERATE_DOC
    static const string _helpDoc = CLEANDNS_DOC_FILTER_HELP;
    string _helpString;
    base64_decode(_helpDoc, _helpString);
    cout << _helpString << endl;
#else
    cout << "Please visit <https://github.com/littlepush/cleandns> for usage." << endl;
#endif
}

void cleandns_version_info() {
    printf( "cleandns version: %s\n", VERSION );
    printf( "target: %s\n", TARGET );

    // All flags
#if CLRD_AUTO_GENERATE_DOC
    cout << "+ ";
#else
    cout << "- ";
#endif
    cout << "CLRD_AUTO_GENERATE_DOC" << endl;

    printf( "Visit <https://github.com/littlepush/cleandns> for more infomation.\n" );
}

service_t _g_service_config;

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
