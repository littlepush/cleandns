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

bool clnd_dns_package::clnd_dns_support_recursive = true;
uint16_t clnd_dns_package::clnd_dns_tid = 1;

// DNS Package class
clnd_dns_package::clnd_dns_package( const char *data, uint16_t len )
{
    memcpy((void *)&transaction_id_, data, sizeof(clnd_dns_package));
}

clnd_dns_package::clnd_dns_package( bool is_query, dns_opcode opcode, uint16_t qd_count)
    : transaction_id_(clnd_dns_tid++), flags_(0), 
    qd_count_( htons(qd_count) ), 
    an_count_(0), ns_count_(0), ar_count_(0) 
{
    uint16_t _h_flag = ntohs(flags_);

    // qr
    if ( !is_query ) _h_flag |= 0x8000;
    else _h_flag &= 0x7FFF;

    // opcode
    uint16_t _op_flag = (uint16_t)opcode;
    _op_flag <<= 13;
    _h_flag |= _op_flag;

    // RD
    _h_flag |= 0x0100;

    flags_ = htons(_h_flag);
};

clnd_dns_package::clnd_dns_package( const clnd_dns_package &rhs )
    : transaction_id_(rhs.transaction_id_), flags_(rhs.flags_),
    qd_count_(rhs.qd_count_), an_count_(rhs.an_count_),
    ns_count_(rhs.ns_count_), ar_count_(rhs.ar_count_) { }

clnd_dns_package& clnd_dns_package::operator= (const clnd_dns_package &rhs )
{
    transaction_id_ = rhs.transaction_id_;
    flags_ = rhs.flags_;
    qd_count_ = rhs.qd_count_;
    an_count_ = rhs.an_count_;
    ns_count_ = rhs.ns_count_;
    ar_count_ = rhs.ar_count_;
    return *this;
}
size_t clnd_dns_package::size() const { return sizeof(uint16_t) * 5; }
const char *const clnd_dns_package::pbuf() { return (char *)this; }

clnd_dns_package * clnd_dns_package::dns_resp_package(string &buf, dns_rcode rcode) const {
    buf.resize(sizeof(clnd_dns_package));
    clnd_dns_package *_presp = new ((void*)&buf[0]) clnd_dns_package(*this);
    uint16_t _h_flag = ntohs(flags_);
    // Query -> Response
    _h_flag |= 0x8000;
    // RCode
    (_h_flag &= 0xFFF0) |= ((uint16_t)rcode & 0x000F);
    _presp->flags_ = htons(_h_flag);
    return _presp;
}

clnd_dns_package * clnd_dns_package::dns_truncation_package( string &buf ) const {
    buf.resize(sizeof(clnd_dns_package));
    clnd_dns_package *_presp = new ((void*)&buf[0]) clnd_dns_package(*this);
    uint16_t _h_flag = ntohs(flags_);
    // Query -> Response
    _h_flag |= 0x8000;
    // Truncation
    _h_flag |= 0x0200;
    _presp->flags_ = htons(_h_flag);
    return _presp;
}

uint16_t clnd_dns_package::get_transaction_id() const 
{
    return ntohs(transaction_id_);
}
bool clnd_dns_package::get_is_query_request() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (_h_flag & 0x8000) == 0;
}
bool clnd_dns_package::get_is_response_request() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (_h_flag & 0x8000) > 0;
}
dns_opcode clnd_dns_package::get_opcode() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (dns_opcode)((_h_flag >>= 13) & 0x000F);
}
bool clnd_dns_package::get_is_authoritative() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (_h_flag & 0x0400) > 0;
}
void clnd_dns_package::set_is_authoritative(bool auth)
{
    uint16_t _h_flag = ntohs(flags_);
    _h_flag |= 0x0400;
    flags_ = htons(_h_flag);
}
bool clnd_dns_package::get_is_truncation() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (_h_flag & 0x0200) > 0;
}
bool clnd_dns_package::get_is_recursive_desired() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (_h_flag & 0x0100) > 0;
}
void clnd_dns_package::set_is_recursive_desired(bool rd)
{
    uint16_t _h_flag = ntohs(flags_);
    _h_flag |= 0x0100;
    flags_ = htons(_h_flag);
}
bool clnd_dns_package::get_is_recursive_available() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (_h_flag & 0x0080) > 0;
}
dns_rcode clnd_dns_package::get_resp_code() const
{
    uint16_t _h_flag = ntohs(flags_);
    return (dns_rcode)(_h_flag & 0x000F);
}

// DNS Method
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
    if ( len < sizeof(clnd_dns_package) ) return -1;
    const char *_pDomain = pkg + sizeof(clnd_dns_package);
    _dns_get_format_domain(_pDomain, domain);
    return 0;
}

int dns_generate_query_package( const string &query_name, string& buffer, dns_qtype qtype ) 
{
    string _fdomain;
    _dns_format_domain(query_name, _fdomain);

    // Buffer
    buffer.resize(sizeof(clnd_dns_package) + _fdomain.size() + 2 * sizeof(uint8_t) + 2 * sizeof(uint8_t));
    // Header
    clnd_dns_package *_pquery = new ((void*)&buffer[0]) clnd_dns_package();
    // Domain
    char *_data_area = (char *)&buffer[0] + sizeof(clnd_dns_package);
    memcpy(_data_area, _fdomain.c_str(), _fdomain.size());
    // Flags
    _data_area += _fdomain.size();
    uint16_t *_flag_area = (uint16_t *)_data_area;
    _flag_area[0] = htons(qtype);
    _flag_area[1] = htons(dns_qclass_in);
    return buffer.size();
}

int dns_generate_tc_package( const string& incoming_pkg, string& buffer ) 
{
    clnd_dns_package _ipkg(incoming_pkg.c_str(), sizeof(clnd_dns_package));
    _ipkg.dns_truncation_package(buffer);
    buffer.resize(incoming_pkg.size());
    memcpy((char *)&buffer[0] + sizeof(clnd_dns_package), 
        incoming_pkg.c_str() + sizeof(clnd_dns_package),
        incoming_pkg.size() - sizeof(clnd_dns_package));
    return buffer.size();
}

int dns_generate_tcp_redirect_package( const string &incoming_pkg, string &buffer )
{
    buffer.resize(incoming_pkg.size() + sizeof(uint16_t));
    uint16_t *_plen = (uint16_t *)&buffer[0];
    *_plen = htons(incoming_pkg.size());
    memcpy((char *)&buffer[2], incoming_pkg.c_str(), incoming_pkg.size());
    return buffer.size();
}

int dns_generate_udp_response_package_from_tcp( const string &incoming_pkg, string &buffer )
{
    buffer.resize(incoming_pkg.size() - sizeof(uint16_t));
    memcpy((char *)&buffer[0], incoming_pkg.c_str() + sizeof(uint16_t), incoming_pkg.size() - sizeof(uint16_t));
    return buffer.size();
}

// cleandns.dns.cpp
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
