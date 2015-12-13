/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : main.cpp
 * Author            : Push Chen
 * Date              : 2014-06-20
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

/*
README.md
----

V0.4 README
===

This is a new version of the cleandns service. In this version, I will make cleandns to support local
dns configuration, auto reload config file and internal web config interface

Roadmap
===

1. 0.4.0: Re-write the whole project with new socketlite library and jsoncpp library. Format the result and dump to specified log file. One can write a script to add the result to some white/black list of iptable or firewall rules.
2. 0.4.1: Auto reload config file with a --reload command. In this version I will make it listens to a file socket to accept any local command input
3. 0.4.2: Internal Web Config Interface. cleandns will have a tiny http web service to accept modify action to the configuration file.

*/

#include "json/json.h"
#include "json/json-forwards.h"
#include "socketlite.h"

#include "json-utility.h"
#include "filter.h"
#include "service.h"

#include <list>
#include <algorithm>

using namespace cpputility;

#if DEBUG
#define DUMP_HEX(...)       dump_hex(__VA_ARGS__)
#else
#define DUMP_HEX(...)
#endif

void clnd_dump_a_records(const char *pkg, unsigned int len, const string &rpeer) {
    string _qdomain;
    vector<uint32_t> _a_records;
    dns_get_a_records(pkg , len, _qdomain, _a_records);
    for ( auto _a_ip : _a_records ) {
        sl_ip _ip(_a_ip);
        linfo << "R:[" << rpeer << "] D:[" << _qdomain << "] A:[" << _ip << "]" << lend;
    }
}

void clnd_get_local_filter(sl_event e, const string& incoming_pkg, lp_clnd_filter f, const string &domain, string& outbuf) {
    shared_ptr<clnd_filter_local> _lf = dynamic_pointer_cast<clnd_filter_local>(f);
    vector<string> _lresult;
    clnd_local_result_type _type;
    _lf->get_result_for_domain(domain, _lresult, _type);

    // A Records
    if ( _type == clnd_local_result_type_A ) {
        vector<uint32_t> _ARecords;
        for ( auto _ip : _lresult ) {
            _ARecords.push_back(network_ipstring_to_inaddr(_ip));
        }
        dns_generate_a_records_resp(
            incoming_pkg.c_str(), 
            incoming_pkg.size(), 
            _ARecords, 
            outbuf);
    } else {
        dns_gnerate_cname_records_resp(
            incoming_pkg.c_str(),
            incoming_pkg.size(),
            _lresult,
            outbuf);            
    }
}
void clnd_tcp_get_local_filter(sl_event e, const string& incoming_pkg, lp_clnd_filter f, const string &domain) {
    string _rbuf;
    clnd_get_local_filter(e, incoming_pkg, f, domain, _rbuf);

    // Generate a tcp package
    string _trbuf;
    dns_generate_tcp_redirect_package(_rbuf, _trbuf);
    sl_tcp_socket_send(e.so, _trbuf);
    sl_socket_close(e.so);
};
void clnd_udp_get_local_filter(sl_event e, const string& incoming_pkg, lp_clnd_filter f, const string &domain) {
    string _rbuf;
    clnd_get_local_filter(e, incoming_pkg, f, domain, _rbuf);
    sl_udp_socket_send(e.so, _rbuf, sl_peerinfo(e.address.sin_addr.s_addr, ntohs(e.address.sin_port)));
};

void clnd_tcp_redirect_to_tcp(sl_event e, sl_event re, const string & incoming_pkg, lp_clnd_filter f) {
    if ( re.event == SL_EVENT_FAILED ) {
        lerror << "failed to connect to the parent server " << f->parent << " for filter " << f->name << lend;
        sl_socket_close(e.so);
        sl_socket_close(re.so);
        return;
    }
    sl_tcp_socket_send(re.so, incoming_pkg);
    sl_tcp_socket_monitor(re.so, [e, f](sl_event re){
        if ( re.event == SL_EVENT_FAILED ) {
            lerror << "failed to get response from " << f->parent << " for filter " << f->name << lend;
            sl_socket_close(e.so);
            sl_socket_close(re.so);
            return;
        }
        string _rbuf;
        sl_tcp_socket_read(re.so, _rbuf);
        clnd_dump_a_records(_rbuf.c_str() + 2, _rbuf.size() - 2, f->parent);
        sl_tcp_socket_send(e.so, _rbuf);

        // Release the socket resource
        sl_socket_close(e.so);
        sl_socket_close(re.so);
    });
}

void clnd_udp_redirect_to_tcp(sl_event e, sl_event re, const string & incoming_pkg, lp_clnd_filter f) {
    if ( re.event == SL_EVENT_FAILED ) {
        lerror << "failed to connect to the parent server " << f->parent << " for filter " << f->name << lend;
        sl_socket_close(re.so);
        return;
    }
    ldebug << "connected to " << f->parent << " via socks5 proxy " << f->socks5 << lend;
    string _tincoming_pkg;
    dns_generate_tcp_redirect_package(incoming_pkg, _tincoming_pkg);
    sl_tcp_socket_send(re.so, _tincoming_pkg);
    sl_tcp_socket_monitor(re.so, [e, f](sl_event re){
        if ( re.event == SL_EVENT_FAILED ) {
            lerror << "failed to get response from " << f->parent << " for filter " << f->name << lend;
            sl_socket_close(re.so);
            return;
        }
        string _rbuf;
        sl_tcp_socket_read(re.so, _rbuf);
        clnd_dump_a_records(_rbuf.c_str() + 2, _rbuf.size() - 2, f->parent);

        string _urbuf;
        dns_generate_udp_response_package_from_tcp(_rbuf, _urbuf);
        sl_udp_socket_send(e.so, _urbuf, sl_peerinfo(e.address.sin_addr.s_addr, ntohs(e.address.sin_port)));

        // Release the socket resource
        sl_socket_close(re.so);
    });
}

int main( int argc, char *argv[] ) {
    Json::Value _config_service;
    Json::Value _config_default_filter;
    bool _reload_config = false;

    if ( argc >= 2 ) {
        int _arg = 1;
        for ( ; _arg < argc; ++_arg ) {
            string _command = argv[_arg];
            if ( _command == "-h" || _command == "--help" ) {
                // Help
                cleandns_help();
                return 0;
            }
            if ( _command == "-v" || _command == "--version" ) {
                // Version
                cleandns_version_info();
                return 0;
            }
            if ( _command == "--filter-help" ) {
                cleandns_filterhelp();
                return 0;
            }
            if ( _command == "-c" || _command == "--config" ) {
                Json::Value _config_root;
                Json::Reader _config_reader;
                string _config_path = argv[++_arg];
                ifstream _config_stream(_config_path, std::ifstream::binary);
                if ( !_config_stream ) {
                    cout << "cannot read the file " << _config_path << endl;
                    return 1;
                }
                if ( !_config_reader.parse(_config_stream, _config_root, false ) ) {
                    cout << _config_reader.getFormattedErrorMessages() << endl;
                    return 1;
                }
                _config_service = check_key_and_get_value(_config_root, "service");
                _config_default_filter = check_key_and_get_value(_config_root, "default");
                if ( _config_root.isMember("filters") ) {
                    Json::Value _filter_nodes = _config_root["filters"];
                    if ( _filter_nodes.isArray() == false ) {
                        cout << "Invalidate config for filters in config file" << endl;
                        return 3;
                    }
                    for ( Json::ArrayIndex i = 0; i < _filter_nodes.size(); ++i ) {
                        //_filter_config_array(_filter_nodes[i]);
                        lp_clnd_filter _f = create_filter_from_config(_filter_nodes[i]);
                        if ( !_f || !(*_f) ) {
                            cout << "failed to load the filter " << i << endl;
                            return 3;
                        }
                        _g_filter_array.push_back(_f);
                    }
                }

                continue;
            }
            if ( _command == "-o" || _command == "--option" ) {
                string _option_string = argv[++_arg];
                vector<string> _opt_com;
                split_string(_option_string, "=", _opt_com);
                if ( _opt_com.size() != 2 ) {
                    cerr << "Invalidate option: " << _option_string << "." << endl;
                    return 2;
                }
                if ( _opt_com[0] == "port" ) {
                    _config_service["port"] = stoi(_opt_com[1], nullptr, 10);
                } else if ( _opt_com[0] == "daemon" ) {
                    if ( _opt_com[1] == "true" ) {
                        _config_service["daemon"] = true;
                    } else if ( _opt_com[1] == "false" ) {
                        _config_service["daemon"] = false;
                    } else {
                        cerr << "Invalidate option: " << _option_string << "." << endl;
                        return 2;
                    }
                } else {
                    _config_service[_opt_com[0]] = _opt_com[1];
                }
                continue;
            }
            if ( _command == "-of" || _command == "--filter-option" ) {
                string _option_string = argv[++_arg];
                vector<string> _opt_com;
                split_string(_option_string, "=", _opt_com);
                if ( _opt_com.size() != 2 ) {
                    cerr << "Invalidate option: " << _option_string << "." << endl;
                    return 3;
                }
                if ( _opt_com[0] == "port" ) {
                    _config_default_filter["port"] = stoi(_opt_com[1], nullptr, 10);
                } else {
                    _config_default_filter[_opt_com[0]] = _opt_com[1];
                }
                continue;
            }
            if ( _command == "-f" || _command == "--filter" ) {
                // _filter_file_array.push_back(argv[++_arg]);
                Json::Reader _filter_reader;
                string _filter_path = argv[++_arg];
                Json::Value _config_filter;
                ifstream _filter_stream(_filter_path, std::ifstream::binary);
                if ( !_filter_reader.parse(_filter_stream, _config_filter, false ) ) {
                    cout << _filter_reader.getFormattedErrorMessages() << endl;
                    return 1;
                }
                lp_clnd_filter _f = create_filter_from_config(_config_filter);
                if ( !_f || !(*_f) ) {
                    cout << "failed to load the filter config file: " << _filter_path << endl;
                    return 3;
                }
                _g_filter_array.push_back(_f);
                continue;
            }
            if ( _command == "-r" || _command == "--reload" ) {
                _reload_config = true;
                continue;
            }
            cerr << "Invalidate argument: " << _command << "." << endl;
            return 1;
        }
    }

    if ( _reload_config ) {
        // To do:...
    }
    // Create the default filter
    _config_default_filter["name"] = "default";
    _config_default_filter["mode"] = "redirect";
    _g_default_filter = create_filter_from_config(_config_default_filter);
    if ( !_g_default_filter || !(*_g_default_filter) ) {
        cout << "Invalidate default filter config" << endl;
        return 3;
    }
    // Start service
    _g_service_config = service_t(new clnd_config_service(_config_service));

    if ( _g_service_config->daemon ) {
        pid_t _pid = fork();
        if ( _pid < 0 ) {
            cerr << "Failed to create child process." << endl;
            return 1;
        }
        if ( _pid > 0 ) {
            // Has create the child process.
            return 0;
        }

        if ( setsid() < 0 ) {
            cerr << "failed to set session leader for child process." << endl;
            return 3;
        }
    }

    string _pidcmd = "mkdir -p $(dirname " + _g_service_config->pidfile + ")";
    system(_pidcmd.c_str());
    FILE *_pidf = fopen(_g_service_config->pidfile.c_str(), "w+");
    if ( _pidf != NULL ) {
        fprintf(_pidf, "%d", (uint32_t)getpid());
        fclose(_pidf);
    }

    // Start the log service at the beginning
    _g_service_config->start_log();

    // Sort the filter
    clnd_global_sort_filter();

    signal_agent _sa([&](){
        remove(_g_service_config->pidfile.c_str());
        linfo << "cleandns terminated" << lend;
    });

    if ( _g_service_config->service_protocol & clnd_protocol_tcp ) {
        SOCKET_T _so = sl_tcp_socket_init();
        sl_tcp_socket_listen(_so, sl_peerinfo(INADDR_ANY, _g_service_config->port), [&](sl_event e) {
            sl_tcp_socket_monitor(e.so, [](sl_event e) {
                string _incoming_buf;
                if ( !sl_tcp_socket_read(e.so, _incoming_buf) ) {
                    lerror << "failed to read data from the incoming socket " << e.so << lend;
                    sl_socket_close(e.so);
                    return;
                }
                string _domain;
                dns_get_domain(_incoming_buf.c_str() + sizeof(uint16_t), 
                    _incoming_buf.size() - sizeof(uint16_t), _domain);

                // Search a filter
                lp_clnd_filter _f = clnd_search_match_filter(_domain);
                // if is local filter, generate a response package
                if ( _f->mode == clnd_filter_mode_local ) {
                    clnd_tcp_get_local_filter(e, _incoming_buf, _f, _domain);
                } 
                // else if use direct redirect, create a tcp socket then send the package and wait,
                else if ( _f->socks5 == false ) {
                    SOCKET_T _rt = sl_tcp_socket_init();
                    sl_tcp_socket_connect(_rt, _f->parent, [e, _f, _incoming_buf](sl_event re){
                        clnd_tcp_redirect_to_tcp(e, re, _incoming_buf, _f);
                    }) ? void() : [_f, e, _rt](){
                        lerror << "failed to connect the parent server " << _f->parent << " for filter " << _f->name << lend;
                        sl_socket_close(e.so);
                        sl_socket_close(_rt);
                    }();
                }
                // else create a tcp socket via proxy, and send then wait.
                else {
                    SOCKET_T _st = sl_tcp_socket_init();
                    sl_tcp_socket_connect(
                        _st, _f->socks5, _f->parent.ipaddress, _f->parent.port_number, 
                        [e, _f, _incoming_buf](sl_event se) {
                        clnd_tcp_redirect_to_tcp(e, se, _incoming_buf, _f);
                    }) ? void() : [_f, e, _st](){
                        lerror 
                            << "failed to connect to " 
                            << _f->parent 
                            << " via socks5 proxy " 
                            << _f->socks5 
                            << " for filter" 
                            << _f->name 
                            << lend;
                        sl_socket_close(e.so);
                        sl_socket_close(_st);
                    }();
                }
            });
        }) ? void() : [](){
            lerror << "failed to listen on " << _g_service_config->port << lend;
            // Internal method: force to safe exit the app
            __g_thread_mutex().unlock();
        }();
    }

    if ( _g_service_config->service_protocol & clnd_protocol_udp ) {
        SOCKET_T _so = sl_udp_socket_init();
        sl_udp_socket_listen(_so, sl_peerinfo(INADDR_ANY, _g_service_config->port), [&](sl_event e){
            sl_peerinfo _ipeer(e.address.sin_addr.s_addr, ntohs(e.address.sin_port));
            string _incoming_buf;
            if ( !sl_udp_socket_read(e.so, e.address, _incoming_buf) ) {
                lerror 
                    << "failed to read data from the incoming socket " 
                    << _ipeer << lend;
                return;
            }
            if ( dns_is_query(_incoming_buf.c_str(), _incoming_buf.size()) == false ) {
                lalert << "the incoming data on " << _ipeer << " is not a dns query request" << lend;
                return;
            }
            string _domain;
            dns_get_domain(_incoming_buf.c_str(), _incoming_buf.size(), _domain);
            // Search a filter
            lp_clnd_filter _f = clnd_search_match_filter(_domain);
            // if is local filter, generate a response package
            if ( _f->mode == clnd_filter_mode_local ) {
                clnd_udp_get_local_filter(e, _incoming_buf, _f, _domain);
            } 
            // else if use direct redirect, create a tcp socket then send the package and wait,
            else if ( _f->socks5 == false ) {
                SOCKET_T _rt = sl_udp_socket_init();
                sl_udp_socket_send(_rt, _incoming_buf, _f->parent);
                sl_udp_socket_monitor(_rt, _f->parent, [e, _f, _incoming_buf, _ipeer](sl_event re){
                    if ( re.event == SL_EVENT_FAILED ) {
                        lerror << "failed to get dns response from udp parent " 
                            << _f->parent << " for filter " << _f->name << lend;
                        sl_socket_close(re.so);
                        return;
                    }
                    string _rbuf;
                    sl_udp_socket_read(re.so, re.address, _rbuf);
                    clnd_dump_a_records(_rbuf.c_str(), _rbuf.size(), _f->parent);
                    sl_socket_close(re.so);
                    sl_udp_socket_send(e.so, _rbuf, _ipeer);
                });
            }
            // else create a tcp socket via proxy, and send then wait.
            else {
                SOCKET_T _st = sl_tcp_socket_init();
                sl_tcp_socket_connect(
                    _st, _f->socks5, _f->parent.ipaddress, _f->parent.port_number, 
                    [e, _f, _incoming_buf](sl_event se) {
                    clnd_udp_redirect_to_tcp(e, se, _incoming_buf, _f);
                }) ? void() : [_f, e, _st](){
                    lerror 
                        << "failed to connect to " 
                        << _f->parent 
                        << " via socks5 proxy " 
                        << _f->socks5 
                        << " for filter" 
                        << _f->name 
                        << lend;
                    sl_socket_close(e.so);
                    sl_socket_close(_st);
                }();
            }
        });
    }

    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
