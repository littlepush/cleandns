/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : upfilter.cpp
 * Author            : Push Chen
 * Date              : 2015-12-14
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

#include "socketlite.h"

int main(int argc, char * argv[])
{
    #ifdef DEBUG
        cp_logger::start(stderr, log_debug);
    #else
        cp_logger::start(stderr, log_notice);
    #endif

    if ( argc < 3 ) {
        lerror << "please set the arguments of the update filter tool" << lend;
        lerror << "usage: upfilter [@server:port] [-a|d] filter_name domain_rule" << lend;
        return 1;
    }

    int _first_arg_index = 1;
    string _server_info = argv[1];
    sl_peerinfo _si("127.0.0.1:1053");
    if ( _server_info[0] == '@' ) {
        _si = _server_info.substr(1);
        _first_arg_index += 1;
    }
    string _cmd = argv[_first_arg_index];
    if ( _cmd[0] == '-' ) {
        if ( _cmd == "-a" ) {
            _cmd = "add_filter";
        } else if ( _cmd == "-d" ) {
            _cmd = "del_filter";
        } else {
            lerror << "unsupport command: " << _cmd << lend;
            return 2;
        }
        _first_arg_index += 1;
    } else {
        _cmd = "add_filter";
    }
    string _filter_name = argv[_first_arg_index];
    string _domain_rule = argv[_first_arg_index + 1];

    ldebug << "filter: " << _filter_name << ", domain: " << _domain_rule << lend;
    ostringstream _oss;
    _oss 
        << "{"
        <<  "\"command\":\"" << _cmd << "\","
        <<  "\"filter\":\"" << _filter_name << "\","
        <<  "\"rule\":\"" << _domain_rule << "\""
        << "}";

    ldebug << "send pkg: " << _oss.str() << lend;
    ldebug << "server: " << _si << lend;

    signal_agent _sa([&](){
        linfo << "quit update filter tool" << lend;
    });

    SOCKET_T _ft = sl_tcp_socket_init();
    if ( !sl_tcp_socket_connect(_ft, _si, [&_oss](sl_event e){
        if ( e.event == SL_EVENT_FAILED ) {
            lerror << "failed to connect to the server" << lend;
            __g_thread_mutex().unlock();
            return;
        }
        if ( !sl_tcp_socket_send(e.so, _oss.str()) ) {
            __g_thread_mutex().unlock();
            return;
        }
        if ( !sl_tcp_socket_monitor(e.so, [](sl_event e){
            if ( e.event == SL_EVENT_FAILED ) {
                __g_thread_mutex().unlock();
                return;
            }
            string _resp;
            if ( !sl_tcp_socket_read(e.so, _resp) ) {
                __g_thread_mutex().unlock();
                return;
            }
            if ( _resp == "{\"errno\":0}" ) {
                lnotice << "success to update the filter" << lend;
            } else {
                lerror << _resp << lend;
            }
            __g_thread_mutex().unlock();
        })) {
            __g_thread_mutex().unlock();
            return;
        }
    })) {
        __g_thread_mutex().unlock();
    }
    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
