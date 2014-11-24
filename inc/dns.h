/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : dns.h
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

#pragma once

#ifndef __CLEAN_DNS_DNS_PACKAGE_H__
#define __CLEAN_DNS_DNS_PACKAGE_H__

#include "config.h"
#include "cf.h"
#include "tcpsocket.h"
#include "udpsocket.h"
#include <vector>
#include <iostream>
using namespace std;

#pragma pack(push, 1)
struct dns_package {
    Uint16          transactionId;
    struct {
        Uint8       qr:1;
        Uint8       opcode:4;
        Uint8       aa:1;
        Uint8       tc:1;
        Uint8       rd:1;
        Uint8       ra:1;
        Uint8       z:3;
        Uint8       rcode:4;
    }               flags;
    Uint16          qdCount;
    Uint16          anCount;
    Uint16          nsCount;
    Uint16          arCount;
};
#pragma pack(pop)

// DNS Filter structure
struct filter_list_node;
typedef pair< string, filter_list_node * >  filter_item;
typedef map< string, filter_list_node * >   component_dictionary;
typedef std::pair< string, unsigned int >   server_info;

struct filter_list_node
{
    vector<filter_item>             prefix_list;
    vector<filter_item>             suffix_list;
    vector<filter_item>             contain_list;
    component_dictionary            component_keys;
    filter_list_node                *everything;
    operator bool() const 
    {
        return (
            prefix_list.size() != 0 || 
            suffix_list.size() != 0 || 
            contain_list.size() != 0 || 
            component_keys.size() != 0 || 
            everything != NULL);
    }
    filter_list_node() : everything(NULL) {}
};

// Get the domain from the dns querying package.
// The query domain seg will store the domain in the following format:
// [length:1Byte][component][length:1Byte][component]...
int dns_get_domain( const char *pkg, unsigned int len, std::string &domain );

typedef enum {
    RP_INHERIT  = 0,
    RP_TCP      = 1,
    RP_UDP      = 2
} redirect_protocol;

class redirect_rule
{
protected:
    typedef struct filter_list_node     _tFLN;
    _tFLN   *m_fl_root;

    string m_name;
    redirect_protocol m_protocol;
    vector<server_info> m_redirect_servers;
    vector<server_info> m_proxy_servers;

public:

    // The name of the redirect rule
    string &rule_name;
    // The protocol used
    redirect_protocol &protocol;

    // Create a redirect rule object with specified config section
    redirect_rule(config_section *section);
    ~redirect_rule();

    // Add a domain filter pattern to the pattern list cache.
    // If any query domain match one pattern in the list, we will
    // redirect the request to the remote dns server according
    // to the configure
    void add_domain_pattern( const string &pattern );

    // Check if specified domain is in the filter list.
    bool is_match_any_filter( const string &domain );

    // Redirect the client to server according to the configure.
    // If the domain match any filter, then redirect, otherwise
    // return false.
    bool redirect_query(cleandns_tcpsocket *client, const string &domain, const string &incoming);
    bool redirect_query(cleandns_udpsocket *client, const string &domain, const string &incoming);
    bool redirect_udp_query(cleandns_tcpsocket *client, const string &incoming);
};

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */