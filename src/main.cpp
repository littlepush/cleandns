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

#include "thread.h"
#include "log.h"
#include "json/json.h"
#include "json/json-forwards.h"
#include "socketlite.h"
#include "string_format.hpp"

#include "json-utility.h"
#include "dns.h"
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
        cp_log(log_info, "R:[%s] D:[%s], A:[%s]", rpeer.c_str(), _qdomain.c_str(), _ip.c_str());
    }
}

void clnd_network_manager( ) {
    register_this_thread();

    sl_tcpsocket _tcpso;
    sl_udpsocket _udpso;

    if ( _g_service_config->service_protocol & clnd_protocol_tcp ) {
        bool _ret = false;
        do {
            _ret = _tcpso.listen(_g_service_config->port);
            usleep( 500000 );
        } while ( _ret == false && this_thread_is_running() );
        if ( this_thread_is_running() == false ) return;
        sl_poller::server().bind_tcp_server(_tcpso.m_socket);
    }

    if ( _g_service_config->service_protocol & clnd_protocol_udp ) {
        bool _ret = false;
        do {
            _ret = _udpso.listen(_g_service_config->port);
            usleep( 500000 );
        } while ( _ret == false && this_thread_is_running() );
        if ( this_thread_is_running() == false ) return;
        sl_poller::server().bind_udp_server(_udpso.m_socket);
    }

    vector<sl_event> _event_list;

    typedef pair<SOCKET_T, struct sockaddr_in> clnd_udp_value;
    typedef pair<struct sockaddr_in, clnd_udp_value> clnd_rudp_value;
    map <SOCKET_T, clnd_rudp_value> _udp_redirect_cache;
    map <SOCKET_T, clnd_udp_value> _udp_proxy_redirect_cache;
    map <SOCKET_T, SOCKET_T> _tcp_redirect_cache;
    map <SOCKET_T, time_t> _alive_cache;

    // Main run loop
    while ( this_thread_is_running() ) {
        _event_list.clear();
        sl_poller::server().fetch_events(_event_list);
        time_t _now = time(NULL);
        for ( auto &_event : _event_list ) {
            if ( _event.event == SL_EVENT_FAILED ) {
                // On error, remove all cache
                if ( _event.socktype == IPPROTO_TCP ) {
                    uint32_t _ipaddr; uint32_t _port;
                    network_peer_info_from_socket(_event.so, _ipaddr, _port);
                    sl_ip _ip(_ipaddr);
                    if ( _udp_proxy_redirect_cache.find(_event.so) != end(_udp_proxy_redirect_cache) ) {
                        _udp_proxy_redirect_cache.erase(_event.so);
                        cp_log(log_warning, "error on udp proxy redirected tcp socket(%d): %s:%u", 
                            _event.so, _ip.c_str(), _port);
                        // Close the tcp socket
                        close(_event.so);
                    } else if ( _tcp_redirect_cache.find(_event.so) != end(_tcp_redirect_cache) ) {
                        // Both close these two socket
                        close(_tcp_redirect_cache[_event.so]);
                        close(_event.so);
                        _tcp_redirect_cache.erase(_event.so);
                        cp_log(log_warning, "error on tcp redirected tcp socket(%d): %s:%u", 
                            _event.so, _ip.c_str(), _port);
                    } else {
                        cp_log(log_error, "unknow error on tcp socket(%d): %s:%u",
                            _event.so, _ip.c_str(), _port);
                    }
                } else {
                    auto _it = _udp_redirect_cache.find(_event.so);
                    sl_peerinfo _pi;
                    //clnd_peerinfo _pi(_event.address.sin_addr.s_addr, _event.address.sin_port);
                    if ( _it != end(_udp_redirect_cache) ) {
                        clnd_rudp_value _rudp_info = _it->second;
                        struct sockaddr_in _rudp_addr = _rudp_info.first;
                        _pi.set_peerinfo(_rudp_addr.sin_addr.s_addr, ntohs(_rudp_addr.sin_port));
                        cp_log(log_warning, "error on udp redirected response socket(%d): %s",
                            _event.so, _pi.c_str());
                        _udp_redirect_cache.erase(_it);
                        close(_event.so);
                    } else {
                        cp_log(log_error, "error on udp socket");
                    }
                }

                // Remove the cache.
                if ( _alive_cache.find(_event.so) != end(_alive_cache) ) {
                    _alive_cache.erase(_event.so);
                }
            } else if ( _event.event == SL_EVENT_ACCEPT ) {
                // New incoming, which will always be TCP
                // Just add to monitor, waiting for some incoming request.
                sl_poller::server().monitor_socket( _event.so, true );
            } else {
                // New Data
                if ( _event.socktype == IPPROTO_UDP ) {
                    sl_peerinfo _pi(_event.address.sin_addr.s_addr, ntohs(_event.address.sin_port));

                    // If is response
                    if ( _udp_redirect_cache.find(_event.so) != end(_udp_redirect_cache) ) {
                        clnd_rudp_value _rudp_info = _udp_redirect_cache[_event.so];
                        sl_udpsocket _ruso(_event.so, _rudp_info.first);
                        struct sockaddr_in _sock_info = _rudp_info.first;
                        _pi.set_peerinfo(_sock_info.sin_addr.s_addr, ntohs(_sock_info.sin_port));

                        clnd_udp_value _udp_info = _rudp_info.second;
                        sl_udpsocket _uso(_udp_info.first, _udp_info.second);
                        sl_peerinfo _opi(_udp_info.second.sin_addr.s_addr, ntohs(_udp_info.second.sin_port));

                        cp_log(log_info, "get response udp package from %s for origin request: %s", _pi.c_str(), _opi.c_str());

                        string _incoming_buf;
                        _ruso.recv(_incoming_buf);

                        #if DEBUG
                        cout << "UDP Response: " << endl;
                        #endif
                        DUMP_HEX(_incoming_buf);
                        // Response from parent
                        // Get response data, then write to log
                        // redirect response
                        _uso.write_data(_incoming_buf);

                        clnd_dump_a_records(_incoming_buf.c_str(), _incoming_buf.size(), _pi);

                        _udp_redirect_cache.erase(_event.so);
                        _alive_cache.erase(_event.so);
                        _ruso.close();
                    } else {
                        cp_log(log_info, "get new incoming udp request from %s.", _pi.c_str());
                        // Get incoming data first.
                        sl_udpsocket _uso(_event.so, _event.address);
                        string _incoming_buf;
                        _uso.recv(_incoming_buf);

                        #if DEBUG
                        cout << "UDP Incoming: " << endl;
                        #endif
                        DUMP_HEX(_incoming_buf);

                        if ( dns_is_query(_incoming_buf.c_str(), _incoming_buf.size()) == false ) {
                            cp_log(log_error, "the incoming (%s) package is not a query request", _pi.c_str());
                            if ( _event.so != _udpso.m_socket ) close(_event.so);
                            continue;
                        }

                        // Get domain
                        string _domain;
                        dns_get_domain(_incoming_buf.c_str(), _incoming_buf.size(), _domain);
                        cp_log(log_info, "try to query domain %s", _domain.c_str());
                        // Search a filter
                        lp_clnd_filter _f = clnd_search_match_filter(_domain);
                        // if is local filter, generate a response package
                        if ( _f->mode == clnd_filter_mode_local ) {
                            cp_log(log_info, "the domain %s match a local zone: %s", 
                                _domain.c_str(), _f->name.c_str());
                            shared_ptr<clnd_filter_local> _lf = dynamic_pointer_cast<clnd_filter_local>(_f);
                            vector<string> _local_result;
                            clnd_local_result_type _type;
                            _lf->get_result_for_domain(_domain, _local_result, _type);

                            string _rbuf;
                            if ( _type == clnd_local_result_type_A ) {
                                vector<uint32_t> _ARecords;
                                for ( auto _ip : _local_result ) {
                                    _ARecords.push_back(network_ipstring_to_inaddr(_ip));
                                }
                                dns_generate_a_records_resp(
                                    _incoming_buf.c_str(), 
                                    _incoming_buf.size(), 
                                    _ARecords, 
                                    _rbuf);
                            } else {
                                dns_gnerate_cname_records_resp(
                                    _incoming_buf.c_str(),
                                    _incoming_buf.size(),
                                    _local_result,
                                    _rbuf
                                    );
                            }
                            DUMP_HEX(_rbuf);
                            _uso.write_data(_rbuf);
                        } 
                        // else if use direct redirect, create a udp socket then send the package and wait, 
                        else if ( _f->socks5 == false ) {
                            cp_log(log_info, "the filter, %s, tell me to use direct redirect on domain %s",
                                _f->name.c_str(), _domain.c_str());
                            if ( _f->protocol & clnd_protocol_udp || _f->protocol == clnd_protocol_inhiert ) {
                                cp_log(log_debug, "redirect incoming(%s) via udp for domain: %s",
                                    _pi.c_str(), _domain.c_str());
                                sl_udpsocket _ruso(true);
                                if ( !_ruso.connect(_f->parent) ) {
                                    cp_log(log_error, "failed to connect parent server via udp for %s(%s)",
                                        _f->name.c_str(), _f->parent.c_str());
                                    continue;
                                }
                                _ruso.set_reusable(true);
                                // Dump debug info
                                uint32_t _ruport;
                                network_sock_info_from_socket(_ruso.m_socket, _ruport);
                                cp_log(log_debug, "redirect domain: %s with local udp connection: 127.0.0.1:%u",
                                    _domain.c_str(), _ruport);

                                _ruso.write_data(_incoming_buf);
                                sl_poller::server().monitor_socket(_ruso.m_socket, true);
                                clnd_udp_value _udp_info = make_pair(_uso.m_socket, _uso.m_sock_addr);
                                _udp_redirect_cache[_ruso.m_socket] = make_pair(_ruso.m_sock_addr, _udp_info);
                                _alive_cache[_ruso.m_socket] = _now;
                            } else {
                                cp_log(log_debug, "redirect incoming(%s) via tcp for domain: %s",
                                    _pi.c_str(), _domain.c_str());
                                sl_tcpsocket _rtso(true);
                                if ( !_rtso.connect(_f->parent) ) {
                                    cp_log(log_error, "failed to connect parent server via tcp for %s(%s)",
                                        _f->name.c_str(), _f->parent.c_str());
                                    continue;
                                }
                                _rtso.set_reusable(true);

                                // Dump debug info
                                uint32_t _ruport;
                                network_sock_info_from_socket(_rtso.m_socket, _ruport);
                                cp_log(log_debug, "redirect domain: %s with local tcp connection: 127.0.0.1:%u",
                                    _domain.c_str(), _ruport);

                                string _rbuf;
                                dns_generate_tcp_redirect_package(_incoming_buf, _rbuf);
                                _rtso.write_data(_rbuf);
                                sl_poller::server().monitor_socket(_rtso.m_socket, true);
                                _udp_proxy_redirect_cache[_rtso.m_socket] = make_pair(_uso.m_socket, _uso.m_sock_addr);
                                _alive_cache[_rtso.m_socket] = _now;
                            }
                        }
                        // else, must be a proxy redirect, create a tcp redirect package, 
                        //  add to redirect cache, then wait for the response
                        else {
                            cp_log(log_info, "the filter(%s) use a socks5 proxy for domain %s",
                                _f->name.c_str(), _domain.c_str());
                            sl_tcpsocket _rtso(true);
                            if ( !_rtso.setup_proxy(_f->socks5.ipaddress, _f->socks5.port_number) ) {
                                cp_log(log_error, "failed to connect parent socks5 proxy for %s(%s)",
                                    _f->name.c_str(), _f->socks5.c_str());
                                continue;
                            }
                            if ( !_rtso.connect(_f->parent) ) {
                                cp_log(log_error, "failed to connect parent server via tcp with proxy for %s(%s)",
                                    _f->name.c_str(), _f->parent.c_str());
                                continue;
                            }
                            _rtso.set_reusable(true);

                            // Dump debug info
                            uint32_t _ruport;
                            network_sock_info_from_socket(_rtso.m_socket, _ruport);
                            cp_log(log_debug, "redirect domain: %s with local tcp connection: 127.0.0.1:%u",
                                _domain.c_str(), _ruport);

                            string _rbuf;
                            dns_generate_tcp_redirect_package(_incoming_buf, _rbuf);
                            _rtso.write_data(_rbuf);
                            sl_poller::server().monitor_socket(_rtso.m_socket, true);
                            _udp_proxy_redirect_cache[_rtso.m_socket] = make_pair(_uso.m_socket, _uso.m_sock_addr);
                            _alive_cache[_rtso.m_socket] = _now;
                        }
                    }
                } else {
                    // TCP
                    sl_tcpsocket _tso(_event.so);
                    string _incoming_buf;
                    _tso.recv(_incoming_buf);

                    uint32_t _ipaddr, _port;
                    network_peer_info_from_socket(_tso.m_socket, _ipaddr, _port);
                    sl_peerinfo _pi(_ipaddr, _port);

                    #if DEBUG
                    cout << "TCP Incoming: " << endl;
                    #endif
                    DUMP_HEX(_incoming_buf);
                    if ( _udp_proxy_redirect_cache.find(_event.so) != end(_udp_proxy_redirect_cache) ) {
                        cp_log(log_debug, "get response from %s via socks5 proxy.", _pi.c_str());
                        // This is a udp proxy redirect, get the response ip, write to log and redirect the response
                        // via origin udp socket.
                        clnd_udp_value _udp_info = _udp_proxy_redirect_cache[_event.so];
                        sl_udpsocket _ruso(_udp_info.first, _udp_info.second);

                        string _rbuf;
                        dns_generate_udp_response_package_from_tcp(_incoming_buf, _rbuf);

                        clnd_dump_a_records(_rbuf.c_str(), _rbuf.size(), _pi);
                        _ruso.write_data(_rbuf);
                        // then remove current so from the cache map
                        _udp_proxy_redirect_cache.erase(_event.so);
                        _alive_cache.erase(_event.so);
                        _tso.close();
                        //_ruso.close();
                    } else if ( _tcp_redirect_cache.find(_event.so) != end(_tcp_redirect_cache) ) {
                        cp_log(log_debug, "get response from %s for direct redirect.", _pi.c_str());
                        // This is a tcp redirect(also can be a sock5 redirect)
                        // get the response then write to log
                        clnd_dump_a_records(_incoming_buf.c_str() + 2, _incoming_buf.size() - 2, _pi);
                        // send back to the origin tcp socket
                        sl_tcpsocket _rtso(_tcp_redirect_cache[_event.so]);
                        _rtso.write_data(_incoming_buf);
                        // remove current so from the cache map
                        _tcp_redirect_cache.erase(_event.so);
                        _alive_cache.erase(_event.so);
                        _tso.close();
                        _rtso.close();
                    } else {
                        // This is a new incoming tcp request
                        cp_log(log_info, "get new incoming tcp request from %s.", _pi.c_str());

                        string _domain;
                        dns_get_domain(_incoming_buf.c_str() + sizeof(uint16_t), 
                            _incoming_buf.size() - sizeof(uint16_t), _domain);

                        // Search a filter
                        lp_clnd_filter _f = clnd_search_match_filter(_domain);
                        // if is local filter, generate a response package
                        if ( _f->mode == clnd_filter_mode_local ) {
                            // todo:
                            shared_ptr<clnd_filter_local> _lf = dynamic_pointer_cast<clnd_filter_local>(_f);
                            vector<string> _local_result;
                            clnd_local_result_type _type;
                            _lf->get_result_for_domain(_domain, _local_result, _type);

                            string _rbuf;
                            if ( _type == clnd_local_result_type_A ) {
                                vector<uint32_t> _ARecords;
                                for ( auto _ip : _local_result ) {
                                    _ARecords.push_back(network_ipstring_to_inaddr(_ip));
                                }
                                dns_generate_a_records_resp(
                                    _incoming_buf.c_str(), 
                                    _incoming_buf.size(), 
                                    _ARecords, 
                                    _rbuf);
                            } else {
                                dns_gnerate_cname_records_resp(
                                    _incoming_buf.c_str(),
                                    _incoming_buf.size(),
                                    _local_result,
                                    _rbuf
                                    );
                            }
                            string _trbuf;
                            dns_generate_tcp_redirect_package(_rbuf, _trbuf);
                            DUMP_HEX(_trbuf);
                            _tso.write_data(_trbuf);
                        } 
                        // else if use direct redirect, create a tcp socket then send the package and wait,
                        else if ( _f->socks5 == false ) {
                            sl_tcpsocket _rtso(true);
                            if ( !_rtso.connect(_f->parent) ) {
                                cp_log(log_error, "failed to connect parent server via tcp for %s(%s)",
                                    _f->name.c_str(), _f->parent.c_str());
                                _tso.close();
                                continue;
                            }
                            _rtso.set_reusable(true);
                            _rtso.write_data(_incoming_buf);
                            sl_poller::server().monitor_socket(_rtso.m_socket, true);
                            _tcp_redirect_cache[_rtso.m_socket] = _tso.m_socket;
                            _alive_cache[_rtso.m_socket] = _now;
                        }
                        // else create a tcp socket via proxy, and send then wait.
                        else {
                            sl_tcpsocket _rtso(true);
                            if ( !_rtso.setup_proxy(_f->socks5.ipaddress, _f->socks5.port_number) ) {
                                cp_log(log_error, "failed to connect parent socks5 proxy for %s(%s)",
                                    _f->name.c_str(), _f->socks5.c_str());
                                continue;
                            }
                            if ( !_rtso.connect(_f->parent) ) {
                                cp_log(log_error, "failed to connect parent server via tcp with proxy for %s(%s)",
                                    _f->name.c_str(), _f->parent.c_str());
                                _tso.close();
                                continue;
                            }
                            _rtso.set_reusable(true);
                            _rtso.write_data(_incoming_buf);
                            sl_poller::server().monitor_socket(_rtso.m_socket, true);
                            _tcp_redirect_cache[_rtso.m_socket] = _tso.m_socket;
                            _alive_cache[_rtso.m_socket] = _now;
                        }
                    }
                }
            }
        }
        list<SOCKET_T> _timeout_sos;
        for ( auto _alive_it = begin(_alive_cache); _alive_it != end(_alive_cache); ++_alive_it ) {
            if ( (_now - _alive_it->second) < 30 ) continue;
            _timeout_sos.push_back(_alive_it->first);

            uint32_t _lport;
            network_sock_info_from_socket(_alive_it->first, _lport);
            cp_log(log_warning, "find a timedout socket on local 127.0.0.1:%u", _lport);

            auto _urit = _udp_redirect_cache.find(_alive_it->first);
            if ( _urit != end(_udp_redirect_cache) ) {
                close(_urit->first);
                _udp_redirect_cache.erase(_urit);
                continue;
            }
            auto _uprit = _udp_proxy_redirect_cache.find(_alive_it->first);
            if ( _uprit != end(_udp_proxy_redirect_cache) ) {
                close(_uprit->first);
                _udp_proxy_redirect_cache.erase(_uprit);
                continue;
            }
            auto _trit = _tcp_redirect_cache.find(_alive_it->first);
            if ( _trit != end(_tcp_redirect_cache) ) {
                close(_trit->first);
                close(_trit->second);
                _tcp_redirect_cache.erase(_trit);
                continue;
            }
        }
        for ( auto _so : _timeout_sos ) {
            _alive_cache.erase(_so);
        }
    }
}

int main( int argc, char *argv[] ) {
    Json::Value _config_root;
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
                Json::Reader _config_reader;
                string _config_path = argv[++_arg];
                ifstream _config_stream(_config_path, std::ifstream::binary);
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
    _g_service_config = new clnd_config_service(_config_service);

    if ( _g_service_config->daemon ) {
        pid_t _pid = fork();
        if ( _pid < 0 ) {
            cerr << "Failed to create child process." << endl;
            delete _g_service_config;
            return 1;
        }
        if ( _pid > 0 ) {
            // Has create the child process.
            delete _g_service_config;
            return 0;
        }

        if ( setsid() < 0 ) {
            cerr << "failed to set session leader for child process." << endl;
            delete _g_service_config;
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

    // Hang current process
    set_signal_handler();

    // create the main loop thread
    thread _main_runloop(clnd_network_manager);

    // Wait for kill signal
    wait_for_exit_signal();
    remove(_g_service_config->pidfile.c_str());
    cp_log(log_info, "cleandns receive terminate signal");

    join_all_threads();
    _main_runloop.join();

    //_main_loop.join();
    //stop_all_services();
    cp_log(log_info, "cleandns terminated");
    cp_log_stop();
    delete _g_service_config;
    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
