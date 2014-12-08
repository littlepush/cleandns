/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : dns.cpp
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

#include "dns.h"

#define _split_string           split_string

// Get the domain from the dns querying package.
// The query domain seg will store the domain in the following format:
// [length:1Byte][component][length:1Byte][component]...
int dns_get_domain( const char *pkg, unsigned int len, std::string &domain )
{
    // the package is too small
    if ( len < sizeof(struct dns_package) ) return -1;

    struct dns_package _dnsPkg;
    memcpy(&_dnsPkg, pkg, sizeof(struct dns_package));
    const char *_pDomain = pkg + sizeof(struct dns_package);
    // Clear the domain
    domain = "";

    for ( ;; ) {
        Int8 _l = 0;
        memcpy(&_l, _pDomain, sizeof(Int8));
        //_l = ntohs(_l);
        if ( _l == 0 ) {
            break;
        }
        _pDomain += sizeof(Int8);
        if ( domain.size() > 0 ) {
            domain += ".";
        }
        domain.append( _pDomain, _l );
        _pDomain += _l;
    }
    return 0;
}

void dns_add_pattern( const string &pattern, filter_list_node *root_node )
{
    filter_list_node *_blNode = root_node;
    vector<string> _components;
    _split_string( pattern, ".", _components );
    for ( int i = (int)_components.size() - 1; i >= 0; --i ) {
        string _com = _components[i];
        //PINFO("Parsing component: " << _com);
        bool _beginWithPattern = _com[0] == '*';
        bool _endWithPattern = _com[_com.size() - 1] == '*';
        if ( _com == "*" ) {
            //PINFO( _com << " stands for everything..." );
            _blNode->everything = new filter_list_node;
            _blNode = _blNode->everything;
            continue;
        }
        if ( _beginWithPattern == false && _endWithPattern == false ) {
            //PINFO(_com << " is a static key");
            if ( _blNode->component_keys.find(_com) == _blNode->component_keys.end() ) {
                _blNode->component_keys[_com] = new filter_list_node;
            } 
            _blNode = _blNode->component_keys[_com];
        } else if ( _beginWithPattern == true && _endWithPattern == true ) {
            //PINFO(_com << " has both patten.");
            bool _hasSameKey = false;
            string _ckey = _com.substr(1, _com.size() - 2);
            //PINFO("static part is: " << _ckey);
            for ( unsigned int c = 0; c < _blNode->contain_list.size(); ++c ) {
                filter_item _item = _blNode->contain_list[c];
                if ( _item.first == _ckey ) {
                    _hasSameKey = true;
                    _blNode = _item.second;
                    break;
                }
            }
            if ( !_hasSameKey ) {
                filter_list_node *_nextLevelNode = new filter_list_node;
                filter_item _newItem = make_pair(_ckey, _nextLevelNode);
                _blNode->contain_list.push_back(_newItem);
                _blNode = _nextLevelNode;
            }
        } else if ( _beginWithPattern == true && _endWithPattern == false ) {
            //PINFO(_com << " is a suffix.");
            bool _hasSameKey = false;
            string _ckey = _com.substr(1);
            //PINFO("static part is: " << _ckey);
            for ( unsigned int c = 0; c < _blNode->suffix_list.size(); ++c ) {
                filter_item _item = _blNode->suffix_list[c];
                if ( _item.first == _ckey ) {
                    _hasSameKey = true;
                    _blNode = _item.second;
                    break;
                }
            }
            if ( !_hasSameKey ) {
                filter_list_node *_nextLevelNode = new filter_list_node;
                filter_item _newItem = make_pair(_ckey, _nextLevelNode);
                _blNode->suffix_list.push_back(_newItem);
                _blNode = _nextLevelNode;
            }
        } else if ( _beginWithPattern == false && _endWithPattern == true ) {
            //PINFO(_com << " is a prefix.");
            bool _hasSameKey = false;
            string _ckey = _com.substr(0, _com.size() - 1);
            //PINFO("static part is: " << _ckey);
            for ( unsigned int c = 0; c < _blNode->prefix_list.size(); ++c ) {
                filter_item _item = _blNode->prefix_list[c];
                if ( _item.first == _ckey ) {
                    _hasSameKey = true;
                    _blNode = _item.second;
                    break;
                }
            }
            if ( !_hasSameKey ) {
                filter_list_node *_nextLevelNode = new filter_list_node;
                filter_item _newItem = make_pair(_ckey, _nextLevelNode);
                _blNode->prefix_list.push_back(_newItem);
                _blNode = _nextLevelNode;
            }
        }
    }
}

bool _string_start_with(const string &value, const string &pattern)
{
    if ( pattern.size() == 0 || value.size() == 0 ) return false;
    if ( pattern.size() > value.size() ) return false;

    return 0 == memcmp( value.c_str(), pattern.c_str(), pattern.size() );
}

bool _string_end_with(const string &value, const string &pattern)
{
    if ( pattern.size() == 0 || value.size() == 0 ) return false;
    if ( pattern.size() > value.size() ) return false;

    return 0 == memcmp( value.c_str() + (value.size() - pattern.size()), 
        pattern.c_str(), pattern.size());
}

bool _domain_match_any_filter_in_subnode( const string &domain, filter_list_node *blnode )
{
    if ( blnode == NULL && domain.size() == 0 ) return true;
    if ( blnode == NULL ) return false;
    if ( blnode->everything ) return true;
    if ( blnode->contain_list.size() ) {
        for ( unsigned int _ctnt = 0; _ctnt < blnode->contain_list.size(); ++_ctnt ) {
            if ( domain.find(blnode->contain_list[_ctnt].first) != string::npos ) return true;
        }
    }
    if ( blnode->suffix_list.size() ) {
        for ( unsigned int _sl = 0; _sl < blnode->suffix_list.size(); ++_sl ) {
            if ( _string_end_with(domain, blnode->suffix_list[_sl].first) ) return true;
        }
    }
    if ( blnode->prefix_list.size() ) {
        for ( unsigned int _pl = 0; _pl < blnode->prefix_list.size(); ++_pl ) {
            if ( _string_start_with(domain, blnode->prefix_list[_pl].first) ) return true;
        }
    }
    if ( blnode->component_keys.size() ) {
        string _com, _leftDomain;
        string::size_type _lastDot = domain.find_last_of('.');
        if ( _lastDot == string::npos ) {
            _com = domain;
        } else {
            _com = domain.substr(_lastDot + 1);
            _leftDomain = domain.substr(0, _lastDot);
        }
        //PINFO(_leftDomain);
        component_dictionary::iterator _it = blnode->component_keys.find(_com);
        if ( _it == blnode->component_keys.end() ) return false;
        return _domain_match_any_filter_in_subnode( _leftDomain, _it->second );
    }
    return false;
}

void redirect_rule::add_domain_pattern( const string &pattern )
{
    dns_add_pattern(pattern, this->m_fl_root);
}

bool redirect_rule::is_match_any_filter( const string &domain )
{
    return _domain_match_any_filter_in_subnode( domain, this->m_fl_root);
}

redirect_rule::redirect_rule(config_section *section)
:rule_name(m_name), protocol(m_protocol)
{
    m_fl_root = new _tFLN;

    // Name
    m_name = section->name;

    // Redirect protocol
    m_protocol = RP_INHERIT;
    if ( section->contains_key("redirect-protocol") ) {
        string _protocol_conf = (*section)["redirect-protocol"];
        if ( _protocol_conf == "inherit" ) {
            m_protocol = RP_INHERIT;
        } else if ( _protocol_conf == "tcp" ) {
            m_protocol = RP_TCP;
        } else if ( _protocol_conf == "udp" ) {
            m_protocol = RP_UDP;
        } else {
            cerr << "warning: invalidate redirect protocol setting: " << _protocol_conf << endl;
            m_protocol = RP_INHERIT;
        }
    }

    // Server list
    if ( section->contains_key("server") == false ) {
        cerr << "warning: invalidate rule setting, missing server list." << endl;
    } else {
        string _server_list = (*section)["server"];
        vector<string> _server_com_list;
        split_string(_server_list, ",", _server_com_list);
        for ( int i = 0; i < (int)_server_com_list.size(); ++i ) {
            string _s_conf = _server_com_list[i];
            vector<string> _server_parts;
            split_string(_s_conf, ":", _server_parts);
            if ( _server_parts.size() != 2 ) {
                cerr << "warning: invalidate server info: " << _s_conf << endl;
                continue;
            }
            server_info _si = make_pair(_server_parts[0], atoi(_server_parts[1].c_str()));
            m_redirect_servers.push_back(_si);
        }
        if ( m_redirect_servers.size() == 0 ) {
            cerr << "warning: invalidate rule setting, no validate server." << endl;
        }
    }

    // Proxy list
    if ( section->contains_key("socks5-proxy") ) {
        if ( m_protocol != RP_TCP ) {
            cerr << "warning: proxy only available when the redirect protocol is set to tcp." << endl;
        } else {
            string _proxy_list = (*section)["socks5-proxy"];
            vector<string> _proxy_com_list;
            split_string(_proxy_list, ",", _proxy_com_list);
            for ( int i = 0; i < (int)_proxy_com_list.size(); ++i ) {
                string _p_conf = _proxy_com_list[i];
                vector<string> _proxy_parts;
                split_string(_p_conf, ":", _proxy_parts);
                if ( _proxy_parts.size() != 2 ) {
                    cerr << "warning: invalidate proxy info: " << _p_conf << endl;
                    continue;
                }
                server_info _pi = make_pair(_proxy_parts[0], atoi(_proxy_parts[1].c_str()));
                m_proxy_servers.push_back(_pi);
            }
        }
    }

    // Add filter list
    config_section *_filter_list = section->sub_section("filter");
    if ( _filter_list == NULL ) {
        // make all domain go through this redirect rule
        this->add_domain_pattern("*");
    } else {
        section->begin_loop();
        config_section::_tnode _node = section->current_node();
        while( _node != section->end() ) {
            this->add_domain_pattern(_node->first);
            section->next_node();
            _node = section->current_node();
        }
    }
}

redirect_rule::~redirect_rule()
{

}
bool redirect_rule::redirect_udp_query(cleandns_tcpsocket *client, const string &incoming)
{
    if ( m_redirect_servers.size() == 0 ) return false;
    cleandns_udpsocket _so;
    for ( int s = 0; s < (int)m_redirect_servers.size(); ++s ) {
        server_info _si = m_redirect_servers[s];
        if ( !_so.connect(_si.first, _si.second) ) continue;
        if ( !_so.write_data(incoming) ) continue;
        string _outcoming;
        if ( !_so.read_data(_outcoming, 5000) ) continue;
        _so.close();
        client->write_data(_outcoming);
        return true;
    }
    return false;
}

bool redirect_rule::redirect_query(cleandns_tcpsocket *client, const string &domain, const string &incoming)
{
    if ( m_redirect_servers.size() == 0 ) return false;
    if ( !this->is_match_any_filter(domain) ) return false; // not match this rule

    bool _ret = false;
    cleandns_tcpsocket _so;
    for ( int s = 0; s < (int)m_redirect_servers.size(); ++s ) {
        _so.close();
        for ( int i = 0; i < (int)m_proxy_servers.size(); ++i ) {
            server_info _pi = m_proxy_servers[i];
            if ( _so.setup_proxy(_pi.first, _pi.second) ) break;
        }
        server_info _si = m_redirect_servers[s];
        if ( !_so.connect(_si.first, _si.second) ) continue;
        if ( !_so.write_data(incoming) ) continue;
        string _outcoming;
        if ( !_so.read_data(_outcoming, 5000) ) continue;
        _so.close();
        client->write_data(_outcoming);
        _ret = true;
        break;
    }
    return _ret;
}
bool redirect_rule::redirect_query(cleandns_udpsocket *client, const string &domain, const string &incoming)
{
    if ( m_redirect_servers.size() == 0 ) return false;
    if ( !this->is_match_any_filter(domain) ) return false; // not match this rule

    if ( m_protocol == RP_TCP ) {   // the same as tcp redirect
        bool _ret = false;
        cleandns_tcpsocket _so;
        for ( int s = 0; s < (int)m_redirect_servers.size(); ++s ) {
            _so.close();
            for ( int i = 0; i < (int)m_proxy_servers.size(); ++i ) {
                server_info _pi = m_proxy_servers[i];
                if ( _so.setup_proxy(_pi.first, _pi.second) ) break;
            }
            server_info _si = m_redirect_servers[s];
            if ( !_so.connect(_si.first, _si.second) ) continue;
            if ( !_so.write_data(incoming) ) continue;
            string _outcoming;
            if ( !_so.read_data(_outcoming, 5000) ) continue;
            _so.close();
            client->write_data(_outcoming);
            _ret = true;
            break;
        }
        return _ret;
    } else {
        bool _ret = false;
        cleandns_udpsocket _so;

        for ( int s = 0; s < (int)m_redirect_servers.size(); ++s ) {
            _so.close();
            server_info _si = m_redirect_servers[s];
            if ( !_so.connect(_si.first, _si.second) ) continue;
            if ( !_so.write_data(incoming) ) continue;
            string _outcoming;
            if ( !_so.read_data(_outcoming, 5000) ) continue;
            _so.close();
            client->write_data(_outcoming);
            _ret = true;
            break;
        }
        return _ret;
    }
}

// cleandns.dns.cpp
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */