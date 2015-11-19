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

#include "dns.h"

#include <list>
#include <algorithm>

using namespace cpputility;

#if DEBUG
#define DUMP_HEX(...)       dump_hex(__VA_ARGS__)
#else
#define DUMP_HEX(...)
#endif

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
typedef struct tag_clnd_ip {
    static uint32_t string_to_ipaddr(const string &ipaddr) {
        vector<string> _components;
        string _clean_ipstring(ipaddr);
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
    string          ip;

    tag_clnd_ip() {}
    tag_clnd_ip(const string &ipaddr) : ip(ipaddr) {}
    tag_clnd_ip(const tag_clnd_ip& rhs) : ip(rhs.ip) {}
    tag_clnd_ip(uint32_t ipaddr) {
        this->operator =(ipaddr);
    }
    operator uint32_t() const {
        return tag_clnd_ip::string_to_ipaddr(this->ip);
    }
    operator string&() { return ip; }
    operator const string&() const { return ip; }

    // Cast operator
    tag_clnd_ip & operator = (const string &ipaddr) {
        ip = ipaddr; return *this;
    }

    tag_clnd_ip & operator = (uint32_t ipaddr) {
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
} clnd_ip;

ostream & operator << (ostream &os, const clnd_ip & ip) {
    os << ip.ip;
    return os;
}

/*!
Peer Info, contains an IP address and a port number.
should be output in the following format: 0.0.0.0:0
*/
typedef struct tag_clnd_peerinfo {
    clnd_ip         ip;
    uint16_t        port;

    void parse_peerinfo_string(const string &format_string) {
        vector<string> _components;
        split_string(format_string, ":", _components);
        if ( _components.size() != 2 ) return;
        ip = _components[0];
        port = stoi(_components[1], nullptr, 10);
    }

    tag_clnd_peerinfo() {}
    tag_clnd_peerinfo(uint32_t addr, uint16_t p) : ip(addr), port(p) { }
    tag_clnd_peerinfo(const string &format_string) : port(0) {
        parse_peerinfo_string(format_string);
    }
    tag_clnd_peerinfo(const string &ipaddr, uint16_t p) : ip(ipaddr), port(p) { }
    tag_clnd_peerinfo(const tag_clnd_peerinfo& rhs):ip(rhs.ip), port(rhs.port) { }
    tag_clnd_peerinfo & operator = (const tag_clnd_peerinfo& rhs) {
        ip = rhs.ip;
        port = rhs.port;
        return *this;
    }

    operator bool() const { return port > 0 && port <= 65535; }
    operator const string () const { 
        ostringstream _oss;
        _oss << ip << ":" << port;
        return _oss.str();
    }
} clnd_peerinfo;

ostream & operator << (ostream &os, const clnd_peerinfo &peer) {
    os << peer.ip << ":" << peer.port;
    return os;
}

typedef enum {
    clnd_protocol_inhiert   = 0,
    clnd_protocol_tcp       = 0x01,
    clnd_protocol_udp       = 0x02,
    clnd_protocol_all       = clnd_protocol_tcp | clnd_protocol_udp,
} clnd_protocol_t;

clnd_protocol_t clnd_protocol_from_string(const string &protocol_string) {
    string _upcase = protocol_string;
    std::transform(_upcase.begin(), _upcase.end(), _upcase.begin(), ::toupper);
    if ( _upcase == "INHIERT" ) return clnd_protocol_inhiert;
    if ( _upcase == "TCP" ) return clnd_protocol_tcp;
    if ( _upcase == "UDP" ) return clnd_protocol_udp;
    if ( _upcase == "ALL" ) return clnd_protocol_all;
    return clnd_protocol_inhiert;
}
string clnd_protocol_string(clnd_protocol_t protocol) {
    switch (protocol) {
        case clnd_protocol_inhiert: return "inhiert";
        case clnd_protocol_tcp: return "tcp";
        case clnd_protocol_udp: return "udp";
        case clnd_protocol_all: return "all";
    };
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

static const Json::Value& check_key_mustbe_array(
    const Json::Value& node, 
    const string &key ) {
    bool _is_type = node[key].isArray();
    if ( !_is_type ) {
        ostringstream _oss;
        _oss << "checking array for key: \"" << key << "\" failed." << endl;
        Json::FastWriter _jsonWriter;
        _oss << "node is: " << _jsonWriter.write(node) << endl;
        throw( runtime_error(_oss.str()) );
    }
    return node[key];
}

static const Json::Value& check_key_with_default(
    const Json::Value& node, 
    const string &key, 
    const Json::Value &defaultValue) {
    if ( node.isMember(key) == false ) return defaultValue;
    return node[key];
}

static void check_json_value_mustby_object(const Json::Value &node) {
    if ( node.isObject() ) return;
    ostringstream _oss;
    Json::FastWriter _jsonWriter;
    _oss << "checking object for node: " << endl << "\t" <<
        _jsonWriter.write(node) << endl << "\033[1;31mFailed\033[0m" << endl;
    throw( runtime_error(_oss.str()) );
}

typedef enum {
    clnd_filter_mode_unknow,
    clnd_filter_mode_local,
    clnd_filter_mode_redirect
} clnd_filter_mode;

static clnd_filter_mode clnd_filter_mode_from_string(const string & mode_string) {
    string _upcase = mode_string;
    std::transform(_upcase.begin(), _upcase.end(), _upcase.begin(), ::toupper);
    if ( _upcase == "LOCAL" ) return clnd_filter_mode_local;
    if ( _upcase == "REDIRECT" ) return clnd_filter_mode_redirect;
    return clnd_filter_mode_unknow;
}

static string clnd_filter_mode_string(clnd_filter_mode mode) {
    switch (mode) {
        case clnd_filter_mode_unknow: return "unknow";
        case clnd_filter_mode_local: return "local";
        case clnd_filter_mode_redirect: return "redirect";
    };
}

class clnd_filter_local;
class clnd_filter_redirect;

class clnd_filter {
protected:
    string                  name_;
    clnd_protocol_t         protocol_;
    clnd_peerinfo           parent_;
    clnd_peerinfo           socks5_;
    string                  after_;
    clnd_filter_mode        mode_;
public: 
    const string &                  name;
    const clnd_protocol_t &         protocol;
    const clnd_peerinfo &           parent;
    const clnd_peerinfo &           socks5;
    const string &                  after;
    const clnd_filter_mode &        mode;

    clnd_filter() : mode_(clnd_filter_mode_unknow), 
    name(name_), protocol(protocol_), parent(parent_), socks5(socks5_), after(after_), mode(mode_) { 
    }

    clnd_filter( const Json::Value &config_node, clnd_filter_mode md ) : mode_(md),
        name(name_), protocol(protocol_), parent(parent_), socks5(socks5_), after(after_), mode(mode_) {
        name_ = check_key_with_default(config_node, "name", untitled_name()).asString();
        protocol_ = clnd_protocol_from_string(
            check_key_with_default(config_node, "protocol", "inhiert").asString()
            );
        if ( mode_ == clnd_filter_mode_local ) {
            parent_.ip = check_key_with_default(config_node, "server", "0.0.0.0").asString();
        } else {
            parent_.ip = check_key_and_get_value(config_node, "server").asString();
        }
        parent_.port = check_key_with_default(config_node, "port", 53).asUInt();
        socks5_ = clnd_peerinfo(
            check_key_with_default(config_node, "socks5", "0.0.0.0:0").asString()
            );
        after_ = check_key_with_default(config_node, "after", "").asString();
        if ( this->go_through_proxy() ) protocol_ = clnd_protocol_tcp;
    }

    operator bool() const { return mode_ != clnd_filter_mode_unknow; }

    virtual void output_detail_info(ostream &os) const { }
    virtual bool is_match_filter(const string &query_domain) const = 0;
    bool go_through_proxy() const { return socks5_; }
};

ostream & operator << (ostream &os, const clnd_filter* filter) {
    os  << "Filter: \033[1;32m" << filter->name << "\033[0m, mode: " 
        << "\033[1;32m" << clnd_filter_mode_string(filter->mode) << "\033[0m" << endl;
    os << "\tusing protocol: \033[1;31m" << clnd_protocol_string(filter->protocol) << "\033[0m" << endl;
    os << "\tparent info: \033[1m" << filter->parent << "\033[0m" << endl;
    os << "\tsocks5 info: \033[1m" << filter->socks5 << "\033[0m" << endl;
    os << "\tafter: \033[1m" << filter->after << "\033[0m" << endl;
    filter->output_detail_info(os);
    return os;
}

typedef enum {
    clnd_local_result_type_A        = 1,
    clnd_local_result_type_CName    = 2
} clnd_local_result_type;

class clnd_filter_local : public clnd_filter {
    string                              domain_;
    map<string, vector<clnd_ip> >       A_records_;
    map<string, string>                 CName_records_;
public:
    const string&                       domain;

    clnd_filter_local(const Json::Value &config_node, clnd_filter_mode md) : 
        clnd_filter(config_node, md), domain(domain_) {
        domain_ = check_key_and_get_value(config_node, "domain").asString();
        if ( config_node.isMember("A") ) {
            Json::Value _A_nodes = check_key_mustbe_array(config_node, "A");
            for ( Json::ArrayIndex i = 0; i < _A_nodes.size(); ++i ) {
                Json::Value _A_rec = _A_nodes[i];
                check_json_value_mustby_object(_A_rec);
                string _sub = check_key_and_get_value(_A_rec, "sub").asString();
                Json::Value _ip_obj = check_key_and_get_value(_A_rec, "ip");
                vector<clnd_ip> _recs;
                if ( _ip_obj.isString() ) {
                    clnd_ip _ip(_ip_obj.asString());
                    _recs.emplace_back(_ip);
                    A_records_[_sub] = _recs;
                } else if ( _ip_obj.isArray() ) {
                    for ( Json::ArrayIndex idx = 0; idx < _ip_obj.size(); ++idx ) {
                        _recs.emplace_back(_ip_obj[idx].asString());
                    }
                    A_records_[_sub] = _recs;
                }
            }
        }
        if ( config_node.isMember("CName") ) {
            Json::Value _C_nodes = check_key_mustbe_array(config_node, "CName");
            for ( Json::ArrayIndex i = 0; i < _C_nodes.size(); ++i ) {
                Json::Value _C_rec = _C_nodes[i];
                check_json_value_mustby_object(_C_rec);
                string _sub = check_key_and_get_value(_C_rec, "sub").asString();
                string _other_domain = check_key_and_get_value(_C_rec, "record").asString();
                CName_records_[_sub] = _other_domain;
            }
        }
    }
    virtual void output_detail_info(ostream &os) const {
        if ( A_records_.size() ) {
            os << "A records: \033[1;33m" << A_records_.size() << "\033[0m" << endl;
            for ( auto _A_it = begin(A_records_); _A_it != end(A_records_); ++_A_it ) {
                os << "\t\033[1;34m" << _A_it->first << "\033[0m: [";
                for ( auto _ip : _A_it->second ) {
                    os << _ip << ", ";
                }
                os << "\b\b";
                os << "]" << endl;
            }
        }

        if ( CName_records_.size() ) {
            os << "CName records: \033[1;33m" << CName_records_.size() << "\033[0m" << endl;
            for ( auto _C_it = begin(CName_records_); _C_it != end(CName_records_); ++_C_it ) {
                os << "\t\033[1;34m" << _C_it->first << "." << domain << "\033[m: " << 
                    _C_it->second << endl;
            }
        }
    }
    virtual bool is_match_filter(const string &query_domain) const {
        if ( query_domain.size() < domain.size() ) return false;
        size_t _qs = query_domain.size();
        size_t _ds = domain.size();
        for ( size_t i = 0; i < domain.size(); ++i ) {
            if ( query_domain[_qs - i - 1] != domain[_ds - i - 1] ) return false;
        }
        if ( query_domain[_qs - _ds - 1] != '.' ) return false;
        string _sub = query_domain.substr(0, _qs - _ds - 1);
        if ( A_records_.find(_sub) != end(A_records_) ) return true;
        if ( CName_records_.find(_sub) != end(CName_records_) ) return true;
        return false;
    }

    void get_result_for_domain(
        const string &query_domain, 
        vector<string> &results, 
        clnd_local_result_type &type) const {

        size_t _qs = query_domain.size();
        size_t _ds = domain.size();
        string _sub = query_domain.substr(0, _qs - _ds - 1);
        if ( A_records_.find(_sub) != end(A_records_) ) {
            auto _a_it = A_records_.find(_sub);
            results.clear();
            for ( auto& _ip_it : _a_it->second ) {
                results.push_back(_ip_it.ip);
            }
            type = clnd_local_result_type_A;
        }
        if ( CName_records_.find(_sub) != end(CName_records_) ) {
            auto _c_it = CName_records_.find(_sub);
            results.push_back(_c_it->second);
            type = clnd_local_result_type_CName;
        }
    }
};

class clnd_filter_redirect : public clnd_filter {
    map< string, bool >             rules_;
public:
    clnd_filter_redirect(const Json::Value &config_node, clnd_filter_mode md) : clnd_filter(config_node, md) {
        if ( config_node.isMember("rulelist") == false ) return;
        Json::Value _rl_node = check_key_mustbe_array(config_node, "rulelist");
        for ( Json::ArrayIndex i = 0; i < _rl_node.size(); ++i ) {
            string _rule_str = _rl_node[i].asString();
            if ( _rule_str[0] == '!' ) {
                string _r = _rule_str.substr(1);
                rules_[trim(_r)] = false;
            } else {
                rules_[trim(_rule_str)] = true;
            }
        }
    }

    virtual void output_detail_info(ostream &os) const {
        os << "Rulelist count: \033[1;33m" << rules_.size() << "\033[0m" << endl;
    }

    virtual bool is_match_filter(const string &query_domain) const {
        auto _rit = rules_.find(query_domain);
        if ( _rit != end(rules_) ) {
            return _rit->second;
        }

        vector<string> _coms;
        split_string(query_domain, ".", _coms);

        vector<string> _query_format;
        for ( int com_count = 1; com_count <= _coms.size(); ++com_count ) {
            for ( int i = 0; i <= (_coms.size() - com_count); ++i ) {
                string _format;
                for ( int j = 0; j < com_count; ++j ) {
                    if ( _format.size() == 0 ) {
                        _format = _coms[i + j];
                    } else {
                        _format += ".";
                        _format += _coms[i + j];
                    }
                }
                _query_format.push_back("*" + _format);
                _query_format.push_back("*" + _format + "*");
                _query_format.push_back(_format + "*");
            }
        }
        for ( auto _f : _query_format ) {
            if ( rules_.find(_f) != end(rules_) ) {
                return true;
            }
        }
        return false;
    }
};

typedef shared_ptr<clnd_filter> lp_clnd_filter;
static lp_clnd_filter create_filter_from_config(const Json::Value &config_node) {
    string _mode = check_key_and_get_value(config_node, "mode").asString();
    clnd_filter_mode _md = clnd_filter_mode_from_string(_mode);
    if ( _md == clnd_filter_mode_unknow ) return lp_clnd_filter(nullptr);
    if ( _md == clnd_filter_mode_local ) return lp_clnd_filter(new clnd_filter_local(config_node, _md));
    if ( _md == clnd_filter_mode_redirect ) return lp_clnd_filter(new clnd_filter_redirect(config_node, _md));
    return lp_clnd_filter(nullptr);
}

class clnd_config_service {
protected:
    clnd_protocol_t         service_protocol_;
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
    const clnd_protocol_t & service_protocol;
    const uint16_t &        port;
    const string &          logpath;
    const cp_log_level &    loglv;
    const bool &            daemon;
    const string &          pidfile;

    clnd_config_service( ) :
        service_protocol(service_protocol_),
        port(port_),
        logpath(logpath_),
        loglv(loglv_),
        daemon(daemon_),
        pidfile(pidfile_){ /* nothing */ }
    virtual ~clnd_config_service() { /* nothing */ }

    clnd_config_service( const Json::Value& config_node ) :
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

clnd_config_service *_g_service_config = NULL;
vector< lp_clnd_filter > _g_filter_array;
lp_clnd_filter _g_default_filter;

void clnd_global_sort_filter() {
    vector< lp_clnd_filter > _local_filters;
    map< string, lp_clnd_filter > _redirect_filters;
    for ( auto _f : _g_filter_array ) {
        if ( _f->mode == clnd_filter_mode_redirect ) {
            _redirect_filters[_f->name] = _f;
        }
        else _local_filters.push_back(_f);
    }
    _g_filter_array.clear();
    _g_filter_array.insert(begin(_g_filter_array), begin(_local_filters), end(_local_filters));

    while ( _redirect_filters.size() > 0 ) {
        list<lp_clnd_filter > _temp_array;
        auto _begin = begin(_redirect_filters);
        auto _last = _begin;
        for ( ; _begin != end(_redirect_filters); ++_begin ) {
            if ( _begin->second->after == _last->second->name ) {
                _last = _begin;
            }
        }
        lp_clnd_filter _f = _last->second;
        do {
            _temp_array.push_front(_f);
            _redirect_filters.erase(_f->name);
            if ( _f->after.length() == 0 ) break;
            if ( _redirect_filters.find(_f->after) == end(_redirect_filters) ) break;
            _f = _redirect_filters[_f->after];
        } while ( true );
        _g_filter_array.insert(end(_g_filter_array), begin(_temp_array), end(_temp_array));
    }
}

// Search first match fitler or return the default one
lp_clnd_filter clnd_search_match_filter(const string &domain)
{
    for ( auto _f : _g_filter_array ) {
        if ( _f->is_match_filter( domain ) ) return _f;
    }
    return _g_default_filter;
}

void clnd_dump_a_records(const char *pkg, unsigned int len, const string &rpeer) {
    string _qdomain;
    vector<uint32_t> _a_records;
    dns_get_a_records(pkg , len, _qdomain, _a_records);
    for ( auto _a_ip : _a_records ) {
        clnd_ip _ip(_a_ip);
        cp_log(log_info, "R:[%s] D:[%s], A:[%s]", rpeer.c_str(), _qdomain.c_str(), _ip.ip.c_str());
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

    // Main run loop
    while ( this_thread_is_running() ) {
        _event_list.clear();
        sl_poller::server().fetch_events(_event_list);
        for ( auto &_event : _event_list ) {
            if ( _event.event == SL_EVENT_FAILED ) {
                // On error, remove all cache
                if ( _event.socktype == IPPROTO_TCP ) {
                    uint32_t _ipaddr; uint32_t _port;
                    network_peer_info_from_socket(_event.so, _ipaddr, _port);
                    clnd_ip _ip(_ipaddr);
                    if ( _udp_proxy_redirect_cache.find(_event.so) != end(_udp_proxy_redirect_cache) ) {
                        _udp_proxy_redirect_cache.erase(_event.so);
                        cp_log(log_warning, "error on udp proxy redirected tcp socket(%d): %s:%u", 
                            _event.so, _ip.ip.c_str(), _port);
                    } else if ( _tcp_redirect_cache.find(_event.so) != end(_tcp_redirect_cache) ) {
                        _tcp_redirect_cache.erase(_event.so);
                        cp_log(log_warning, "error on tcp redirected tcp socket(%d): %s:%u", 
                            _event.so, _ip.ip.c_str(), _port);
                    }
                } else {
                    auto _it = _udp_redirect_cache.find(_event.so);
                    clnd_peerinfo _pi;
                    //clnd_peerinfo _pi(_event.address.sin_addr.s_addr, _event.address.sin_port);
                    if ( _it != end(_udp_redirect_cache) ) {
                        clnd_rudp_value _rudp_info = _it->second;
                        struct sockaddr_in _rudp_addr = _rudp_info.first;
                        _pi.ip = _rudp_addr.sin_addr.s_addr;
                        _pi.port = _rudp_addr.sin_port;
                        cp_log(log_warning, "error on udp redirected response socket(%d): %s:%u",
                            _event.so, _pi.ip.ip.c_str(), _pi.port);
                        _udp_redirect_cache.erase(_it);
                    } else {
                        cp_log(log_warning, "error on udp socket");
                    }
                }
            } else if ( _event.event == SL_EVENT_ACCEPT ) {
                // New incoming, which will always be TCP
                // Just add to monitor, waiting for some incoming request.
                sl_poller::server().monitor_socket( _event.so, true );
            } else {
                // New Data
                if ( _event.socktype == IPPROTO_UDP ) {
                    clnd_peerinfo _pi(_event.address.sin_addr.s_addr, _event.address.sin_port);

                    // If is response
                    if ( _udp_redirect_cache.find(_event.so) != end(_udp_redirect_cache) ) {
                        clnd_rudp_value _rudp_info = _udp_redirect_cache[_event.so];
                        sl_udpsocket _ruso(_event.so, _rudp_info.first);
                        struct sockaddr_in _sock_info = _rudp_info.first;
                        _pi.ip = _sock_info.sin_addr.s_addr;
                        _pi.port = _sock_info.sin_port;

                        string _incoming_buf;
                        _ruso.recv(_incoming_buf);

                        #if DEBUG
                        cout << "UDP Response: " << endl;
                        #endif
                        DUMP_HEX(_incoming_buf);
                        // Response from parent
                        // Get response data, then write to log
                        // redirect response
                        clnd_udp_value _udp_info = _rudp_info.second;
                        sl_udpsocket _uso(_udp_info.first, _udp_info.second);
                        _uso.write_data(_incoming_buf);

                        clnd_dump_a_records(_incoming_buf.c_str(), _incoming_buf.size(), _pi);

                        _udp_redirect_cache.erase(_event.so);
                    } else {
                        cp_log(log_info, "get new incoming udp request from %s:%u.",
                            _pi.ip.ip.c_str(), _pi.port);
                        // Get incoming data first.
                        sl_udpsocket _uso(_event.so, _event.address);
                        string _incoming_buf;
                        _uso.recv(_incoming_buf);

                        #if DEBUG
                        cout << "UDP Incoming: " << endl;
                        #endif
                        DUMP_HEX(_incoming_buf);

                        // Get domain
                        string _domain;
                        dns_get_domain(_incoming_buf.c_str(), _incoming_buf.size(), _domain);
                        cp_log(log_info, "try to query domain %s", _domain.c_str());
                        // Search a filter
                        lp_clnd_filter _f = clnd_search_match_filter(_domain);
                        // if is local filter, generate a response package
                        if ( _f->mode == clnd_filter_mode_local ) {
                            shared_ptr<clnd_filter_local> _lf = dynamic_pointer_cast<clnd_filter_local>(_f);
                            vector<string> _local_result;
                            clnd_local_result_type _type;
                            _lf->get_result_for_domain(_domain, _local_result, _type);

                            string _rbuf;
                            if ( _type == clnd_local_result_type_A ) {
                                vector<uint32_t> _ARecords;
                                for ( auto _ip : _local_result ) {
                                    _ARecords.push_back(clnd_ip::string_to_ipaddr(_ip));
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
                                cp_log(log_debug, "redirect incoming(%s:%u) via udp for domain: %s",
                                    _pi.ip.ip.c_str(), _pi.port, _domain.c_str());
                                sl_udpsocket _ruso(true);
                                if ( !_ruso.connect(_f->parent.ip, _f->parent.port) ) {
                                    cp_log(log_error, "failed to connect parent server via udp for %s(%s:%u)",
                                        _f->name.c_str(), _f->parent.ip.ip.c_str(), _f->parent.port);
                                    continue;
                                }
                                _ruso.write_data(_incoming_buf);
                                sl_poller::server().monitor_socket(_ruso.m_socket, true);
                                clnd_udp_value _udp_info = make_pair(_uso.m_socket, _uso.m_sock_addr);
                                _udp_redirect_cache[_ruso.m_socket] = make_pair(_ruso.m_sock_addr, _udp_info);
                            } else {
                                cp_log(log_debug, "redirect incoming(%s:%u) via tcp for domain: %s",
                                    _pi.ip.ip.c_str(), _pi.port, _domain.c_str());
                                sl_tcpsocket _rtso(true);
                                if ( !_rtso.connect(_f->parent.ip, _f->parent.port) ) {
                                    cp_log(log_error, "failed to connect parent server via tcp for %s(%s:%u)",
                                        _f->name.c_str(), _f->parent.ip.ip.c_str(), _f->parent.port);
                                    continue;
                                }
                                string _rbuf;
                                dns_generate_tcp_redirect_package(_incoming_buf, _rbuf);
                                _rtso.write_data(_rbuf);
                                sl_poller::server().monitor_socket(_rtso.m_socket, true);
                                _udp_proxy_redirect_cache[_rtso.m_socket] = make_pair(_uso.m_socket, _uso.m_sock_addr);
                            }
                        }
                        // else, must be a proxy redirect, create a tcp redirect package, 
                        //  add to redirect cache, then wait for the response
                        else {
                            cp_log(log_info, "the filter(%s) use a socks5 proxy for domain %s",
                                _f->name.c_str(), _domain.c_str());
                            sl_tcpsocket _rtso(true);
                            if ( !_rtso.setup_proxy(_f->socks5.ip, _f->socks5.port) ) {
                                cp_log(log_error, "failed to connect parent socks5 proxy for %s(%s:%u)",
                                    _f->name.c_str(), _f->socks5.ip.ip.c_str(), _f->socks5.port);
                                continue;
                            }
                            if ( !_rtso.connect(_f->parent.ip, _f->parent.port) ) {
                                cp_log(log_error, "failed to connect parent server via tcp with proxy for %s(%s:%u)",
                                    _f->name.c_str(), _f->parent.ip.ip.c_str(), _f->parent.port);
                                continue;
                            }
                            string _rbuf;
                            dns_generate_tcp_redirect_package(_incoming_buf, _rbuf);
                            _rtso.write_data(_rbuf);
                            sl_poller::server().monitor_socket(_rtso.m_socket, true);
                            _udp_proxy_redirect_cache[_rtso.m_socket] = make_pair(_uso.m_socket, _uso.m_sock_addr);
                        }
                    }
                } else {
                    // TCP
                    sl_tcpsocket _tso(_event.so);
                    string _incoming_buf;
                    _tso.recv(_incoming_buf);

                    uint32_t _ipaddr, _port;
                    network_peer_info_from_socket(_tso.m_socket, _ipaddr, _port);
                    clnd_peerinfo _pi(_ipaddr, _port);

                    #if DEBUG
                    cout << "TCP Incoming: " << endl;
                    #endif
                    DUMP_HEX(_incoming_buf);
                    if ( _udp_proxy_redirect_cache.find(_event.so) != end(_udp_proxy_redirect_cache) ) {
                        cp_log(log_debug, "get response from %s:%u via socks5 proxy.",
                            _pi.ip.ip.c_str(), _pi.port);
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
                    } else if ( _tcp_redirect_cache.find(_event.so) != end(_tcp_redirect_cache) ) {
                        cp_log(log_debug, "get response from %s:%u for direct redirect.",
                            _pi.ip.ip.c_str(), _pi.port);
                        // This is a tcp redirect(also can be a sock5 redirect)
                        // get the response then write to log
                        clnd_dump_a_records(_incoming_buf.c_str() + 2, _incoming_buf.size() - 2, _pi);
                        // send back to the origin tcp socket
                        sl_tcpsocket _rtso(_tcp_redirect_cache[_event.so]);
                        _rtso.write_data(_incoming_buf);
                        // remove current so from the cache map
                        _tcp_redirect_cache.erase(_event.so);
                    } else {
                        // This is a new incoming tcp request
                        cp_log(log_info, "get new incoming tcp request from %s:%u.",
                            _pi.ip.ip.c_str(), _pi.port);

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
                                    _ARecords.push_back(clnd_ip::string_to_ipaddr(_ip));
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
                            if ( !_rtso.connect(_f->parent.ip, _f->parent.port) ) {
                                cp_log(log_error, "failed to connect parent server via tcp for %s(%s:%u)",
                                    _f->name.c_str(), _f->parent.ip.ip.c_str(), _f->parent.port);
                                _tso.close();
                                continue;
                            }
                            _rtso.write_data(_incoming_buf);
                            sl_poller::server().monitor_socket(_rtso.m_socket, true);
                            _tcp_redirect_cache[_rtso.m_socket] = _tso.m_socket;
                        }
                        // else create a tcp socket via proxy, and send then wait.
                        else {
                            sl_tcpsocket _rtso(true);
                            if ( !_rtso.setup_proxy(_f->socks5.ip, _f->socks5.port) ) {
                                cp_log(log_error, "failed to connect parent socks5 proxy for %s(%s:%u)",
                                    _f->name.c_str(), _f->socks5.ip.ip.c_str(), _f->socks5.port);
                                continue;
                            }
                            if ( !_rtso.connect(_f->parent.ip, _f->parent.port) ) {
                                cp_log(log_error, "failed to connect parent server via tcp with proxy for %s(%s:%u)",
                                    _f->name.c_str(), _f->parent.ip.ip.c_str(), _f->parent.port);
                                _tso.close();
                                continue;
                            }
                            _rtso.write_data(_incoming_buf);
                            sl_poller::server().monitor_socket(_rtso.m_socket, true);
                            _tcp_redirect_cache[_rtso.m_socket] = _tso.m_socket;
                        }
                    }
                }
            }
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
