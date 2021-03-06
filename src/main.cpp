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

    bool _system_error = false;

    if ( _g_service_config->service_protocol & clnd_protocol_tcp ) {
        if ( INVALIDATE_SOCKET == sl_tcp_socket_listen(sl_peerinfo(INADDR_ANY, _g_service_config->port), [&](sl_event e) {
            sl_socket_monitor(e.so, 3, [](sl_event e) {
                string _incoming_buf;
                if ( !sl_tcp_socket_read(e.so, _incoming_buf) ) {
                    lerror << "failed to read data from the incoming socket " << e.so << lend;
                    sl_socket_close(e.so);
                    return;
                }
                sl_dns_packet _dpkt(_incoming_buf, true);
                if ( !_dpkt.is_validate_query() ) {
                    lwarning 
                        << "receive an invalidate dns query packet from " 
                        << sl_peerinfo(e.address) << lend;
                    sl_socket_close(e.so);
                    return;
                }

                string _domain(move(_dpkt.get_query_domain()));

                // Search a filter
                lp_clnd_filter _f = clnd_search_match_filter(_domain);
                // if is local filter, generate a response packet
                if ( _f->mode == clnd_filter_mode_local ) {    
                    shared_ptr<clnd_filter_local> _lf = dynamic_pointer_cast<clnd_filter_local>(_f);
                    vector<string> _lresult;
                    clnd_local_result_type _type;
                    _lf->get_result_for_domain(_domain, _lresult, _type);

                    sl_dns_packet _rpkt(_dpkt);
                    // A Records
                    if ( _type == clnd_local_result_type_A ) {
                        vector<sl_ip> _a_records;
                        for ( auto &_ip : _lresult ) {
                            _a_records.emplace_back(sl_ip(_ip));
                        }
                        _rpkt.set_A_records(_a_records);
                    } else {
                        _rpkt.set_C_Names(_lresult);
                    }
                    _rpkt.set_is_recursive_available(true);
                    // Send and close
                    sl_tcp_socket_send(e.so, _rpkt.to_tcp_packet(), [=](sl_event e) {
                        sl_socket_close(e.so);
                    });
                    // DUMP local result
                    string _tstr = (_type == clnd_local_result_type_A ? "A:[" : "C:[");
                    for ( auto& _r : _lresult ) {
                        linfo << "R:[localhost] D:[" << _domain << "] " << _tstr << _r << "]" << lend;
                    }
                }
                else {
                    sl_async_redirect_dns_query(_dpkt, _f->parent, _f->socks5, true, [=](const sl_dns_packet &rpkt){
                        vector<sl_ip> _a_records(move(rpkt.get_A_records()));
                        for ( auto &_ip : _a_records ) {
                            linfo << "R:[" << _f->parent << "] D:[" << _domain << "] A:[" << _ip << "]" << lend;
                            if ( _f->socks5 ) {
                                _g_service_config->add_a_record_cache(_ip);
                            }
                        }
                        sl_tcp_socket_send(e.so, rpkt.to_tcp_packet(), [=](sl_event e) {
                            sl_socket_close(e.so);
                        });
                    });
                }
            });
        }) ) _system_error = true;
    }

	sl_events::server().setup(50, NULL);

    if ( _g_service_config->service_protocol & clnd_protocol_udp ) {
        SOCKET_T _so = sl_udp_socket_init(sl_peerinfo(INADDR_ANY, _g_service_config->port));
        sl_udp_socket_listen(_so, [&](sl_event e){
            sl_peerinfo _ipeer(e.address.sin_addr.s_addr, ntohs(e.address.sin_port));
            string _incoming_buf;
            if ( !sl_udp_socket_read(e.so, e.address, _incoming_buf) ) {
                lerror 
                    << "failed to read data from the incoming socket " 
                    << _ipeer << lend;
                return;
            }
            sl_dns_packet _dpkt(_incoming_buf);
            if ( !_dpkt.is_validate_query() ) {
                lwarning 
                    << "receive an invalidate dns query packet from " 
                    << sl_peerinfo(e.address) << lend;
                return;
            }
            string _domain(move(_dpkt.get_query_domain()));
            linfo << "the incoming request " << _ipeer << " want to query domain: " << _domain << lend;

            // Search a filter
            lp_clnd_filter _f = clnd_search_match_filter(_domain);
            // if is local filter, generate a response packet
            if ( _f->mode == clnd_filter_mode_local ) {
                shared_ptr<clnd_filter_local> _lf = dynamic_pointer_cast<clnd_filter_local>(_f);
                vector<string> _lresult;
                clnd_local_result_type _type;
                _lf->get_result_for_domain(_domain, _lresult, _type);

                sl_dns_packet _rpkt(_dpkt);
                // A Records
                if ( _type == clnd_local_result_type_A ) {
                    vector<sl_ip> _a_records;
                    for ( auto &_ip : _lresult ) {
                        _a_records.emplace_back(sl_ip(_ip));
                    }
                    _rpkt.set_A_records(_a_records);
                } else {
                    _rpkt.set_C_Names(_lresult);
                }
                _rpkt.set_is_recursive_available(true);
                // Send and close
                sl_udp_socket_send(e.so, sl_peerinfo(e.address.sin_addr.s_addr, ntohs(e.address.sin_port)), _rpkt);
                // DUMP local result
                string _tstr = (_type == clnd_local_result_type_A ? "A:[" : "C:[");
                for ( auto& _r : _lresult ) {
                    linfo << "R:[localhost] D:[" << _domain << "] " << _tstr << _r << "]" << lend;
                }
            } 
            else {
                sl_async_redirect_dns_query(_dpkt, _f->parent, _f->socks5, false, [=](const sl_dns_packet &rpkt){
                    vector<sl_ip> _a_records(move(rpkt.get_A_records()));
                    for ( auto &_ip : _a_records ) {
                        linfo << "R:[" << _f->parent << "] D:[" << _domain << "] A:[" << _ip << "]" << lend;
                        if ( _f->socks5 ) {
                            _g_service_config->add_a_record_cache(_ip);
                        }
                    }
                    sl_udp_socket_send(e.so, sl_peerinfo(e.address.sin_addr.s_addr, ntohs(e.address.sin_port)), rpkt);
                });
            }
        });
    }

    do {
        if ( INVALIDATE_SOCKET == sl_tcp_socket_listen(sl_peerinfo(INADDR_ANY, _g_service_config->control_port), [&](sl_event e) {
            sl_socket_monitor(e.so, 3, [](sl_event e) {
                if ( e.event == SL_EVENT_FAILED ) {
                    sl_socket_close(e.so);
                    return;
                }
                string _req;
                if ( !sl_tcp_socket_read(e.so, _req) ) {
                    sl_socket_close(e.so);
                    return;
                }
                Json::Value _cmd_node;
                Json::Reader _cmd_reader;
                if ( !_cmd_reader.parse(_req, _cmd_node, false) ) {
                    lerror << "the request is not even a json object" << lend;
                    sl_socket_close(e.so);
                    return;
                }

                string _cmd = check_key_with_default(_cmd_node, "command", "").asString();
                if ( _cmd.size() == 0 ) {
                    lerror << "the request is not a validate control request" << lend;
                    sl_socket_close(e.so);
                    return;
                }
                if ( _cmd == "add_filter" || _cmd == "del_filter" ) {
                    string _filter = check_key_with_default(_cmd_node, "filter", "default").asString();
                    string _domain_rule = check_key_with_default(_cmd_node, "rule", "localhost").asString();

                    if ( _filter == "default" || _domain_rule == "localhost" ) {
                        lerror << "invalidate command for add_filter" << lend;
                        sl_socket_close(e.so);
                        return;
                    }

                    linfo 
                        << "get a control command \'" << _cmd << "\' for filter: " 
                        << _filter << ", rule: " << _domain_rule << lend;
                    lp_clnd_filter _f = clnd_find_filter_by_name(_filter);
                    if ( !_f ) {
                        lerror << "no such filter in the list" << lend;
                        sl_tcp_socket_send(e.so, "{\"errno\": 1,\"errmsg\":\"no such filter in the list\"}", [](sl_event e){
                            sl_socket_close(e.so);
                        });
                    } else if ( _f->mode != clnd_filter_mode_redirect ) {
                        ostringstream _oss;
                        _oss << "filter: " << _f->name << " is not a redirect filter, cannot add rule";
                        lerror << _oss.str() << lend;
                        ostringstream _msg;
                        _msg << "{\"errno\": 2,\"errmsg\":\"" << _oss.str() << "\"}";
                        sl_tcp_socket_send(e.so, _msg.str(), [](sl_event e){
                            sl_socket_close(e.so);
                        });
                    } else {
                        shared_ptr<clnd_filter_redirect> _rf = dynamic_pointer_cast<clnd_filter_redirect>(_f);
                        if ( _cmd == "add_filter" ) {
                            _rf->add_rule(_domain_rule);
                        } else {
                            _rf->del_rule(_domain_rule);
                        }
                        sl_tcp_socket_send(e.so, "{\"errno\":0}", [](sl_event e){
                            sl_socket_close(e.so);
                        });
                    }
                }
            });
        }) ) _system_error = true;
    } while(false);

    if ( _g_service_config->gateway && _g_service_config->gateway_port <= 65535 ) {
        if ( INVALIDATE_SOCKET == sl_tcp_socket_listen(sl_peerinfo(INADDR_ANY, _g_service_config->gateway_port), [&](sl_event e){
            sl_peerinfo _orgnl = sl_tcp_get_original_dest(e.so);
            if ( !_orgnl ) {
                lerror << "failed to get the original dest info" << lend;
                lerror << "maybe this is a BSD system, which does not support SO_ORIGINAL_DST" << lend;
                sl_socket_close(e.so);
                return;
            }
			//sl_peerinfo _lpi(e.address.sin_addr.s_addr, ntohs(e.address.sin_port));
			uint32_t _laddr, _lport;
			network_peer_info_from_socket(e.so, _laddr, _lport);
			sl_peerinfo _lpi(_laddr, _lport);
			ldebug 
                << "the incoming connection " << _lpi << " want to connect to " 
                << _orgnl << " via current gateway" << lend;
            if ( !_g_service_config->allow_access_from_ip(_lpi.ipaddress) ) {
                lwarning << "the incoming connection " << _lpi << " is not allowed, block it." << lend;
                sl_socket_close(e.so);
                return;
            }
            sl_peerinfo _socks5 = sl_peerinfo::nan();
            // Search for dns cache
            if ( _g_service_config->is_ip_in_a_record_cache(_orgnl.ipaddress) ) {
                _socks5 = _g_service_config->gateway_socks5;
            }

            sl_tcp_socket_redirect(e.so, _orgnl, _socks5);
        }) ) _system_error = true;
    }

    if ( !_system_error ) {
        signal_agent _sa([&](){
            remove(_g_service_config->pidfile.c_str());
            linfo << "cleandns terminated" << lend;
        });
    } else {
        return 1;
    }
    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
