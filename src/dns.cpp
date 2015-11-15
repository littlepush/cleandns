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
#include "string_format.hpp"

void _dns_format_domain(const string &dname, string &buf) {
    buf.resize(dname.size() + 2);
    char *_buf = &buf[0];
    vector<string> _com;
    cpputility::split_string(dname, ".", _com);
    for ( auto& _dp : _com ) {
        _buf[0] = (uint8_t)(_dp.size());
        for ( unsigned i = 0; i < _dp.size(); ++i ) {
            _buf[i + 1] = _dp[i];
        }
        _buf += (_dp.size() + 1);
    }
    _buf[0] = '\0';
}

void _dns_get_format_domain( const char *data, string &domain ) {
    domain.clear();
    for ( ;; ) {
        uint8_t _l = data[0];
        if ( _l == 0 ) break;
        data++;
        if ( domain.size() > 0 ) domain += ".";
        domain.append( data, _l );
        data += _l;
    }
}

// Get the domain from the dns querying package.
// The query domain seg will store the domain in the following format:
// [length:1Byte][component][length:1Byte][component]...
int dns_get_domain( const char *pkg, unsigned int len, std::string &domain )
{
    // the package is too small
    if ( len < sizeof(dns_header) ) return -1;

    dns_header _dnsPkg;
    memcpy(&_dnsPkg, pkg, sizeof(dns_header));
    const char *_pDomain = pkg + sizeof(dns_header);
    _dns_get_format_domain(_pDomain, domain);
    return 0;
}

int dns_generate_query_package( const string &query_name, string& buffer, dns_qtype qtype ) {
    static uint16_t g_tid = 0;
    string _fdomain;
    _dns_format_domain(query_name, _fdomain);
    buffer.resize(sizeof(dns_header) + _fdomain.size() + 2 * sizeof(uint8_t) + 2 * sizeof(uint8_t));
    dns_header *_pheader = (dns_header *)&buffer[0];
    memset(_pheader, sizeof(dns_header), 0);
    _pheader->transaction_id = (++g_tid);
    uint16_t *_pflags = (uint16_t *)((char *)_pheader + sizeof(uint16_t));
    *_pflags = htons(0x0100);
    _pheader->qd_count = htons(1);
    char *_data_area = (char *)&buffer[0] + sizeof(dns_header);
    memcpy(_data_area, _fdomain.c_str(), _fdomain.size());
    _data_area += _fdomain.size();
    uint16_t *_flag_area = (uint16_t *)_data_area;
    _flag_area[0] = htons(qtype);
    _flag_area[1] = htons(dns_qclass_in);
    return buffer.size();
}

int dns_generate_tc_package( const string& incoming_pkg, string& buffer ) {
    buffer.clear();
    buffer.insert(0, incoming_pkg.c_str(), incoming_pkg.size());
    dns_header *_pheader = (dns_header *)&buffer[0];
    _pheader->flags.qr = true;
    _pheader->flags.tc = true;
    return buffer.size();
}
// cleandns.dns.cpp
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
