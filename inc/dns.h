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

// Add a domain filter pattern to the black list cache.
// If any query domain match one pattern in the list, we will
// redirect the request to the remote dns server use tcp socket.
// So you can setup a socks5 proxy to get clean dns
void dns_add_filter_pattern( const string &pattern );

// Check if specified domain is in the filter list.
bool domain_match_filter( const string &domain );

// Add a domain pattern to the white list cache.
// If any query domain match the pattern in white list, we will
// redirect the query to the local dns server.
void dns_add_whitelist_pattern( const string &pattern );

// Check if specified domain is in the white list.
bool domain_match_whitelist( const string &domain );

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */