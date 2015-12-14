/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : filter.cpp
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

#include "filter.h"
#include "json-utility.h"

static string untitled_name() {
    static int _id = 1;
    ostringstream _oss;
    _oss << "untitled_" << _id++;
    return _oss.str();
}

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
        default: return "inhiert";
    };
}

clnd_filter_mode clnd_filter_mode_from_string(const string & mode_string) {
    string _upcase = mode_string;
    std::transform(_upcase.begin(), _upcase.end(), _upcase.begin(), ::toupper);
    if ( _upcase == "LOCAL" ) return clnd_filter_mode_local;
    if ( _upcase == "REDIRECT" ) return clnd_filter_mode_redirect;
    return clnd_filter_mode_unknow;
}

string clnd_filter_mode_string(clnd_filter_mode mode) {
    switch (mode) {
        case clnd_filter_mode_unknow: return "unknow";
        case clnd_filter_mode_local: return "local";
        case clnd_filter_mode_redirect: return "redirect";
        default: return "unknow";
    };
}

clnd_filter::clnd_filter() : 
    mode_(clnd_filter_mode_unknow), 
    name(name_), protocol(protocol_), 
    parent(parent_), socks5(socks5_), 
    after(after_), mode(mode_) 
{ }

clnd_filter::clnd_filter( const Json::Value &config_node, clnd_filter_mode md ) : 
    mode_(md),
    name(name_), protocol(protocol_), 
    parent(parent_), socks5(socks5_), 
    after(after_), mode(mode_) 
{
    name_ = check_key_with_default(config_node, "name", untitled_name()).asString();
    protocol_ = clnd_protocol_from_string(
        check_key_with_default(config_node, "protocol", "inhiert").asString()
        );
    string _server_address;
    if ( mode_ == clnd_filter_mode_local ) {
        _server_address = check_key_with_default(config_node, "server", "0.0.0.0").asString();
    } else {
        _server_address = check_key_and_get_value(config_node, "server").asString();
    }
    parent_.set_peerinfo(_server_address, check_key_with_default(config_node, "port", 53).asUInt());
    socks5_ = sl_peerinfo(
        check_key_with_default(config_node, "socks5", "0.0.0.0:0").asString()
        );
    after_ = check_key_with_default(config_node, "after", "").asString();
    if ( this->go_through_proxy() ) protocol_ = clnd_protocol_tcp;
}

clnd_filter::operator bool() const { return mode_ != clnd_filter_mode_unknow; }
void clnd_filter::output_detail_info(ostream &os) const { }
bool clnd_filter::go_through_proxy() const { return socks5_; }

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

// Local
clnd_filter_local::clnd_filter_local(const Json::Value &config_node, clnd_filter_mode md) : 
    clnd_filter(config_node, md), domain(domain_) 
{
    domain_ = check_key_and_get_value(config_node, "domain").asString();
    if ( config_node.isMember("A") ) {
        Json::Value _A_nodes = check_key_mustbe_array(config_node, "A");
        for ( Json::ArrayIndex i = 0; i < _A_nodes.size(); ++i ) {
            Json::Value _A_rec = _A_nodes[i];
            check_json_value_mustby_object(_A_rec);
            string _sub = check_key_and_get_value(_A_rec, "sub").asString();
            Json::Value _ip_obj = check_key_and_get_value(_A_rec, "ip");
            vector<string> _recs;
            if ( _ip_obj.isString() ) {
                _recs.push_back(_ip_obj.asString());
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
void clnd_filter_local::output_detail_info(ostream &os) const {
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
bool clnd_filter_local::is_match_filter(const string &query_domain) const {
    if ( query_domain.size() < domain.size() ) return false;
    if ( query_domain.size() == domain.size() && query_domain == domain ) {
        if ( A_records_.find("@") != end(A_records_) ) return true;
        return false;
    }
    size_t _qs = query_domain.size();
    size_t _ds = domain.size();
    for ( size_t i = 0; i < domain.size(); ++i ) {
        if ( query_domain[_qs - i - 1] != domain[_ds - i - 1] ) return false;
    }
    if ( query_domain[_qs - _ds - 1] != '.' ) return false;
    string _sub = query_domain.substr(0, _qs - _ds - 1);
    if ( A_records_.find("*") != end(A_records_) ) return true;
    if ( A_records_.find(_sub) != end(A_records_) ) return true;
    if ( CName_records_.find("*") != end(CName_records_) ) return true;
    if ( CName_records_.find(_sub) != end(CName_records_) ) return true;
    return false;
}

void clnd_filter_local::get_result_for_domain(
    const string &query_domain, 
    vector<string> &results, 
    clnd_local_result_type &type) const 
{
    size_t _qs = query_domain.size();
    size_t _ds = domain.size();
    if ( _qs == _ds ) {
        auto _a_it = A_records_.find("@");
        results.clear();
        for ( auto& _ip_it : _a_it->second ) {
            results.push_back(_ip_it);
        }
        type = clnd_local_result_type_A;
        return;
    }

    string _sub = query_domain.substr(0, _qs - _ds - 1);
    if ( A_records_.find(_sub) != end(A_records_) ) {
        auto _a_it = A_records_.find(_sub);
        results.clear();
        for ( auto& _ip_it : _a_it->second ) {
            results.push_back(_ip_it);
        }
        type = clnd_local_result_type_A;
    }
    if ( A_records_.find("*") != end(A_records_) ) {
        auto _a_it = A_records_.find("*");
        results.clear();
        for ( auto& _ip_it : _a_it->second ) {
            results.push_back(_ip_it);
        }
        type = clnd_local_result_type_A;
    }
    if ( CName_records_.find(_sub) != end(CName_records_) ) {
        auto _c_it = CName_records_.find(_sub);
        results.push_back(_c_it->second);
        type = clnd_local_result_type_CName;
    }
    if ( CName_records_.find("*") != end(CName_records_) ) {
        auto _c_it = CName_records_.find("*");
        results.push_back(_c_it->second);
        type = clnd_local_result_type_CName;
    }
}

// Redirect
clnd_filter_redirect::clnd_filter_redirect(const Json::Value &config_node, clnd_filter_mode md) : 
    clnd_filter(config_node, md) 
{
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

void clnd_filter_redirect::output_detail_info(ostream &os) const {
    os << "Rulelist count: \033[1;33m" << rules_.size() << "\033[0m" << endl;
}

bool clnd_filter_redirect::is_match_filter(const string &query_domain) const {
    auto _rit = rules_.find(query_domain);
    if ( _rit != end(rules_) ) {
        return _rit->second;
    }

    vector<string> _coms;
    split_string(query_domain, ".", _coms);

    vector<string> _query_format;
    for ( size_t com_count = 1; com_count <= _coms.size(); ++com_count ) {
        for ( size_t i = 0; i <= (_coms.size() - com_count); ++i ) {
            string _format;
            for ( size_t j = 0; j < com_count; ++j ) {
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
    lock_guard<mutex> _(filter_mutex_);
    for ( auto _f : _query_format ) {
        if ( rules_.find(_f) != end(rules_) ) {
            return true;
        }
    }
    return false;
}

void clnd_filter_redirect::add_rule(const string& domain_rule) {
    lock_guard<mutex> _(filter_mutex_);
    rules_[domain_rule] = true;
}
void clnd_filter_redirect::del_rule(const string& domain_rule) {
    lock_guard<mutex> _(filter_mutex_);
    rules_.erase(domain_rule);
}


lp_clnd_filter create_filter_from_config(const Json::Value &config_node) {
    string _mode = check_key_and_get_value(config_node, "mode").asString();
    clnd_filter_mode _md = clnd_filter_mode_from_string(_mode);
    if ( _md == clnd_filter_mode_unknow ) return lp_clnd_filter(nullptr);
    if ( _md == clnd_filter_mode_local ) return lp_clnd_filter(new clnd_filter_local(config_node, _md));
    if ( _md == clnd_filter_mode_redirect ) return lp_clnd_filter(new clnd_filter_redirect(config_node, _md));
    return lp_clnd_filter(nullptr);
}

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

lp_clnd_filter clnd_find_filter_by_name(const string& filter_name)
{
    for ( auto _f : _g_filter_array ) {
        if ( _f->name == filter_name ) return _f;
    }
    return lp_clnd_filter(NULL);
}
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
