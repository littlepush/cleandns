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
#include "base64.h"
#include "string_format.hpp"

#include <algorithm>

using namespace cpputility;

#ifdef CLRD_AUTO_GENERATE_DOC
#include "doc_header_auto_generate.h"
#endif

static string untitled_name() {
    static int _id = 1;
    ostringstream _oss;
    _oss << "untitled_" << _id++;
    return _oss.str();
}

/*!
The IP object, compatible with std::string and uint32_t
This is a ipv4 ip address class.
*/
typedef struct tag_clrd_ip {
    string          ip;

    tag_clrd_ip() {}
    tag_clrd_ip(const string &ipaddr) : ip(ipaddr) {}
    tag_clrd_ip(const tag_clrd_ip& rhs) : ip(rhs.ip) {}
    tag_clrd_ip(uint32_t ipaddr) {
        this->operator =(ipaddr);
    }
    operator uint32_t() const {
        vector<string> _components;
        string _clean_ipstring(this->ip);
        trim(_clean_ipstring);
        // Split the ip address
        split_string(_clean_ipstring, ".", _components);
        if ( _components.size() != 4 ) return 0;

        uint32_t _ipaddr = 0;
        for ( int i = 0; i < 4; ++i ) {
            int _i = stoi(_components[i], nullptr, 10);
            if ( _i < 0 || _i > 255 ) return 0;
            _ipaddr |= (_i << ((3 - i) * 8));
        }
        return _ipaddr;
    }
    operator string&() { return ip; }

    // Cast operator
    tag_clrd_ip & operator = (const string &ipaddr) {
        ip = ipaddr; return *this;
    }

    tag_clrd_ip & operator = (uint32_t ipaddr) {
        char _ip_[16] = {0};
        sprintf( _ip_, "%u.%u.%u.%u",
            (ipaddr >> (0 * 8)) & 0x00FF,
            (ipaddr >> (1 * 8)) & 0x00FF,
            (ipaddr >> (2 * 8)) & 0x00FF,
            (ipaddr >> (3 * 8)) & 0x00FF 
        );
        ip = string(_ip_);
        return *this;
    }
} clrd_ip;

/*!
Peer Info, contains an IP address and a port number.
should be output in the following format: 0.0.0.0:0
*/
typedef struct tag_clrd_peerinfo {
    clrd_ip         ip;
    uint16_t        port;

    void parse_peerinfo_string(const string &format_string) {
        vector<string> _components;
        split_string(format_string, ":", _components);
        if ( _components.size() != 2 ) return;
        ip = _components[0];
        stoi(_components[1], nullptr, 10);
    }

    tag_clrd_peerinfo() {}
    tag_clrd_peerinfo(const string &format_string) : port(0) {
        parse_peerinfo_string(format_string);
    }
    tag_clrd_peerinfo(const string &ipaddr, uint16_t p) : ip(ipaddr), port(p) { }
    tag_clrd_peerinfo(const tag_clrd_peerinfo& rhs):ip(rhs.ip), port(rhs.port) { }
    tag_clrd_peerinfo & operator = (const tag_clrd_peerinfo& rhs) {
        ip = rhs.ip;
        port = rhs.port;
        return *this;
    }

    operator bool() const { return port > 0 && port <= 65535; }
} clrd_peerinfo;

ostream & operator << (ostream &os, const clrd_peerinfo &peer) {
    os << peer.ip << ":" << peer.port;
    return os;
}

typedef enum {
    clrd_protocol_inhiert   = 0,
    clrd_protocol_tcp       = 0x01,
    clrd_protocol_udp       = 0x02,
    clrd_protocol_all       = clrd_protocol_tcp | clrd_protocol_udp,
} clrd_protocol_t;

clrd_protocol_t clrd_protocol_from_string(const string &protocol_string) {
    string _upcase = protocol_string;
    std::transform(_upcase.begin(), _upcase.end(), _upcase.begin(), ::toupper);
    if ( _upcase == "INHIERT" ) return clrd_protocol_inhiert;
    if ( _upcase == "TCP" ) return clrd_protocol_tcp;
    if ( _upcase == "UDP" ) return clrd_protocol_udp;
    if ( _upcase == "ALL" ) return clrd_protocol_all;
    return clrd_protocol_inhiert;
}

static const Json::Value& check_key_and_get_value(const Json::Value& node, const string &key) {
    if ( node.isMember(key) == false ) {
        ostringstream _oss;
        _oss << "missing \"" << key << "\"" << endl;
        Json::FastWriter _jsonWriter;
        _oss << "check on config node: " << _jsonWriter.write(node) << endl;
        throw( runtime_error(_oss.str()) );
    }
    return node[key];
}

static const Json::Value& check_key_with_default(const Json::Value& node, const string &key, const Json::Value &defaultValue) {
    if ( node.isMember(key) == false ) return defaultValue;
    return node[key];
}

typedef enum {
    clrd_filter_mode_unknow,
    clrd_filter_mode_local,
    clrd_filter_mode_redirect
} clrd_filter_mode;

static clrd_filter_mode clrd_filter_mode_from_string(const string & mode_string) {
    string _upcase = mode_string;
    std::transform(_upcase.begin(), _upcase.end(), _upcase.begin(), ::toupper);
    if ( _upcase == "LOCAL" ) return clrd_filter_mode_local;
    if ( _upcase == "REDIRECT" ) return clrd_filter_mode_redirect;
    return clrd_filter_mode_unknow;
}

class clrd_filter_local;
class clrd_filter_redirect;

class clrd_filter {
protected:
    string                  name_;
    clrd_protocol_t         protocol_;
    clrd_peerinfo           parent_;
    clrd_peerinfo           socks5_;
    string                  after_;
    clrd_filter_mode        mode_;
public: 
    const string &                  name;
    const clrd_protocol_t &         protocol;
    const clrd_peerinfo &           parent;
    const clrd_peerinfo &           socks5;
    const string &                  after;
    const clrd_filter_mode &        mode;

    clrd_filter() : mode_(clrd_filter_mode_unknow), 
    name(name_), protocol(protocol_), parent(parent_), socks5(socks5_), after(after_), mode(mode_) { 
    }

    clrd_filter( const Json::Value &config_node, clrd_filter_mode md ) : mode_(md),
        name(name_), protocol(protocol_), parent(parent_), socks5(socks5_), after(after_), mode(mode_) {
        name_ = check_key_with_default(config_node, "name", untitled_name()).asString();
        protocol_ = clrd_protocol_from_string(
            check_key_with_default(config_node, "protocol", "inhiert").asString()
            );
        parent_.ip = check_key_and_get_value(config_node, "server").asString();
        parent_.port = check_key_with_default(config_node, "port", 53).asUInt();
        socks5_ = clrd_peerinfo(
            check_key_with_default(config_node, "socks5", "0.0.0.0:0").asString()
            );
        after_ = check_key_with_default(config_node, "after", "").asString();
    }

    operator bool() const { return mode_ != clrd_filter_mode_unknow; }

    bool go_through_proxy() const { return socks5_; }
};

class clrd_filter_local : public clrd_filter {
public:
    clrd_filter_local(const Json::Value &config_node, clrd_filter_mode md) : clrd_filter(config_node, md) {

    }
};

class clrd_filter_redirect : public clrd_filter {
public:
    clrd_filter_redirect(const Json::Value &config_node, clrd_filter_mode md) : clrd_filter(config_node, md) {

    }
};

typedef shared_ptr<clrd_filter> lp_clrd_filter;
static lp_clrd_filter create_filter_from_config(const Json::Value &config_node) {
    string _mode = check_key_and_get_value(config_node, "mode").asString();
    clrd_filter_mode _md = clrd_filter_mode_from_string(_mode);
    if ( _md == clrd_filter_mode_unknow ) return lp_clrd_filter(nullptr);
    if ( _md == clrd_filter_mode_local ) return lp_clrd_filter(new clrd_filter_local(config_node, _md));
    if ( _md == clrd_filter_mode_redirect ) return lp_clrd_filter(new clrd_filter_redirect(config_node, _md));
    return lp_clrd_filter(nullptr);
}

class clrd_config_service {
protected:
    clrd_protocol_t         service_protocol_;
    uint16_t                port_;
    string                  logpath_;
    cp_log_level            loglv_;
    bool                    daemon_;
    string                  pidfile_;

    cp_log_level _loglv_from_string(const string& loglv_string) {
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
public:

    // const reference
    const clrd_protocol_t & service_protocol;
    const uint16_t &        port;
    const string &          logpath;
    const cp_log_level &    loglv;
    const bool &            daemon;
    const string &          pidfile;

    clrd_config_service( ) :
        service_protocol(service_protocol_),
        port(port_),
        logpath(logpath_),
        loglv(loglv_),
        daemon(daemon_),
        pidfile(pidfile_){ /* nothing */ }
    virtual ~clrd_config_service() { /* nothing */ }

    clrd_config_service( const Json::Value& config_node ) :
        service_protocol(service_protocol_),
        port(port_),
        logpath(logpath_),
        loglv(loglv_),
        daemon(daemon_),
        pidfile(pidfile_) 
    {
        // Service
        service_protocol_ = clrd_protocol_from_string(
            check_key_with_default(config_node, "protocol", "all").asString());
        port_ = check_key_with_default(config_node, "port", 53).asUInt();
        logpath_ = check_key_with_default(config_node, "logpath", "syslog").asString();
        loglv_ = _loglv_from_string(
            check_key_with_default(config_node, "loglevel", "info").asString()
            );
        daemon_ = check_key_with_default(config_node, "daemon", true).asBool();
        pidfile_ = check_key_with_default(config_node, "pidfile", "/var/run/cleandns/pid").asString();
    }

    void start_log() const {
        // Stop the existed log
        cp_log_stop();
        // Check system log path
        if ( logpath_ == "syslog" ) {
            cp_log_start(loglv_);
        } else if ( logpath_ == "stdout" ) {
            cp_log_start(stdout, loglv_);
        } else if ( logpath_ == "stderr" ) {
            cp_log_start(stderr, loglv_);
        } else {
            cp_log_start(logpath_, loglv_);
        }
    }
};
// Default redirect rule
//redirect_rule *_default_rule;
//vector<redirect_rule *> _rules;

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

clrd_config_service *_g_service_config = NULL;
vector< lp_clrd_filter > _g_filter_array;
lp_clrd_filter _g_default_filter;

void clrd_global_sort_filter() {
    vector< lp_clrd_filter > _local_filters;
    map< string, lp_clrd_filter > _redirect_filters;
    for ( auto _f : _g_filter_array ) {
        if ( _f->mode == clrd_filter_mode_redirect ) {
            _redirect_filters[_f->name] = _f;
        }
        else _local_filters.push_back(_f);
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
                        lp_clrd_filter _f = create_filter_from_config(_filter_nodes[i]);
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
                lp_clrd_filter _f = create_filter_from_config(_config_filter);
                if ( !_f || !(*_f) ) {
                    cout << "failed to load the filter config file: " << _filter_path << endl;
                    return 3;
                }
                _g_filter_array.push_back(_f);
                continue;
            }
            cerr << "Invalidate argument: " << _command << "." << endl;
            return 1;
        }
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
    _g_service_config = new clrd_config_service(_config_service);
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
    clrd_global_sort_filter();

    // Hang current process
    set_signal_handler();

    // create the main loop thread
    //thread _main_loop(tiny_distributer_worker);

    // Wait for kill signal
    wait_for_exit_signal();
    remove(_g_service_config->pidfile.c_str());
    cp_log(log_info, "cleandns receive terminate signal");

    join_all_threads();

    //_main_loop.join();
    //stop_all_services();
    cp_log(log_info, "tinydst terminated");
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
