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
    service_protocol(service_protocol_),
    port(port_),
    logpath(logpath_),
    loglv(loglv_),
    daemon(daemon_),
    pidfile(pidfile_){ /* nothing */ }
clnd_config_service::~clnd_config_service() { /* nothing */ }

clnd_config_service::clnd_config_service( const Json::Value& config_node ) :
    service_protocol(service_protocol_),
    port(port_),
    logpath(logpath_),
    loglv(loglv_),
    daemon(daemon_),
    pidfile(pidfile_) 
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
