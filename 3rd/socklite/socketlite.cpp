/*
    socklite -- a C++ socket library for Linux/Windows/iOS
    Copyright (C) 2014  Push Chen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    You can connect me by email: littlepush@gmail.com, 
    or @me on twitter: @littlepush
*/
// This is an amalgamate file for socketlite

// Current Version: 0.6-rc3

#include "socketlite.h"
// src/dns.cpp
#include <arpa/inet.h>

#ifdef SOCK_LITE_INTEGRATION_DNS

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

clnd_dns_package * clnd_dns_package::dns_resp_package(string &buf, dns_rcode rcode, uint16_t ancount) const {
    buf.resize(sizeof(clnd_dns_package));
    //clnd_dns_package *_presp = new ((void*)&buf[0]) clnd_dns_package(*this);
    clnd_dns_package *_presp = (clnd_dns_package *)&buf[0];
    *_presp = *this;
    uint16_t _h_flag = ntohs(flags_);
    // Query -> Response
    _h_flag |= 0x8000;
    // RCode
    (_h_flag &= 0xFFF0) |= ((uint16_t)rcode & 0x000F);
    _presp->flags_ = htons(_h_flag);
    // Answer Count
    _presp->an_count_ = htons(ancount);
    return _presp;
}

clnd_dns_package * clnd_dns_package::dns_truncation_package( string &buf ) const {
    buf.resize(sizeof(clnd_dns_package));
    clnd_dns_package *_presp = (clnd_dns_package *)&buf[0];
    *_presp = *this;
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
uint16_t clnd_dns_package::get_qd_count() const
{
    return ntohs(qd_count_);
}
uint16_t clnd_dns_package::get_an_count() const
{
    return ntohs(an_count_);
}
uint16_t clnd_dns_package::get_ns_count() const
{
    return ntohs(ns_count_);
}
uint16_t clnd_dns_package::get_ar_count() const
{
    return ntohs(ar_count_);
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

int _dns_get_format_domain( const char *data, string &domain ) {
    domain.clear();
    for ( ;; ) {
        uint8_t _l = data[0];
        if ( _l == 0 ) break;
        data++;
        if ( domain.size() > 0 ) domain += ".";
        domain.append( data, _l );
        data += _l;
    }
    return domain.size() + 2;
}

int _dns_get_format_domain( const char *begin_of_domain, const char *begin_of_pkg, string &domain ) {
    domain.clear();
    int _readsize = 0;
    for ( ;; ) {
        uint8_t _l = begin_of_domain[_readsize];
        _readsize += 1;
        if ( _l & 0xC0 ) {
            // This is an offset
            string _reset_domain;
            uint16_t _offset = 0;
            if ( (_l & 0x3F) == 0 ) {
                // Use 2 bits
                _offset = ntohs(*(uint16_t *)(begin_of_domain + _readsize - 1));
                _offset &= 0x3FFF;
                _readsize += 1; // read more
            } else {
                _offset = (uint16_t)(_l & 0x3F);
                _readsize += 1;
            }
            _dns_get_format_domain(begin_of_pkg + _offset, _reset_domain);
            domain += _reset_domain;
            break;
        } else {
            if ( _l == 0 ) break;
            if ( domain.size() > 0 ) domain += ".";
            domain.append(begin_of_domain + _readsize, _l);
            _readsize += _l;
        }
    }
    return _readsize;
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
    //clnd_dns_package *_pquery = (clnd_dns_package*)&buffer[0]);
    clnd_dns_package _query_pkg;
    memcpy(&buffer[0], _query_pkg.pbuf(), _query_pkg.size());
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

void dns_generate_a_records_resp( const char *pkg, unsigned int len, vector<uint32_t> ipaddress, string &buf )
{
    // Resp Header
    clnd_dns_package _ipkg(pkg, len);
    _ipkg.dns_resp_package(buf, dns_rcode_noerr, (uint16_t)ipaddress.size());

    // All length: incoming package(header + query domain) + 2bytes domain-name(offset to query domain) + 
    // 2 bytes type(A) + 2 bytes class(IN) + 4 bytes(TTL) + 2bytes(r-length) + 4bytes(r-data, ipaddr)
    buf.resize( len + (2 + 2 + 2 + 4 + 2 + 4) * ipaddress.size() );
    // Query Domain
    memcpy(
        &buf[0] + sizeof(clnd_dns_package), 
        pkg + sizeof(clnd_dns_package),
        len - sizeof(clnd_dns_package)
        );
    // Offset
    uint16_t _name_offset = sizeof(clnd_dns_package);
    _name_offset |= 0xC000;
    _name_offset = htons(_name_offset);
    // Generate the RR
    size_t _boffset = len;
    for ( auto _ip : ipaddress ) {
        // Name
        uint16_t *_pname = (uint16_t *)(&buf[0] + _boffset);
        *_pname = _name_offset;
        _boffset += sizeof(uint16_t);

        // Type
        uint16_t *_ptype = (uint16_t *)(&buf[0] + _boffset);
        *_ptype = htons((uint16_t)dns_qtype_host);
        _boffset += sizeof(uint16_t);

        // Class
        uint16_t *_pclass = (uint16_t *)(&buf[0] + _boffset);
        *_pclass = htons((uint16_t)dns_qclass_in);
        _boffset += sizeof(uint16_t);

        // TTL
        uint32_t *_pttl = (uint32_t *)(&buf[0] + _boffset);
        *_pttl = htonl(30 * 60);    // 30 mins
        _boffset += sizeof(uint32_t);

        // RLENGTH
        uint16_t *_prlen = (uint16_t *)(&buf[0] + _boffset);
        *_prlen = htons(4);
        _boffset += sizeof(uint16_t);

        // RDATA
        uint32_t *_prdata = (uint32_t *)(&buf[0] + _boffset);
        *_prdata = htonl((uint32_t)_ip);
        _boffset += sizeof(uint32_t);
    }
}

// Generate response package for specified query domain
void dns_generate_a_records_resp( 
    const string &query_domain, 
    uint16_t trans_id, 
    const vector<uint32_t> & iplist, 
    string &buf )
{
    string _query_pkg;
    dns_generate_query_package(query_domain, _query_pkg);
    clnd_dns_package *_pkg = (clnd_dns_package *)&_query_pkg[0];
    uint16_t* _ptid = (uint16_t *)_pkg;
    *_ptid = htons(trans_id);
    dns_generate_a_records_resp(_query_pkg.c_str(), _query_pkg.size(), iplist, buf);
}

void dns_gnerate_cname_records_resp( const char *pkg, unsigned int len, vector<string> cnamelist, string &buf )
{
    // Resp Header
    clnd_dns_package _ipkg(pkg, len);
    _ipkg.dns_resp_package(buf, dns_rcode_noerr, (uint16_t)cnamelist.size());

    // All length: incoming package(header + query domain) + 2bytes domain-name(offset to query domain) + 
    // 2 bytes type(CName) + 2 bytes class(IN) + 4 bytes(TTL) + 2bytes(r-length) + r-length bytes(r-data, cname)
    //buf.resize( len + (2 + 2 + 2 + 4 + 2 + 4) * cnamelist.size() );
    buf.resize(len);
    // Query Domain
    memcpy(
        &buf[0] + sizeof(clnd_dns_package), 
        pkg + sizeof(clnd_dns_package),
        len - sizeof(clnd_dns_package)
        );
    // Offset
    uint16_t _name_offset = sizeof(clnd_dns_package);
    _name_offset |= 0xC000;
    _name_offset = htons(_name_offset);
    // Generate the RR
    size_t _boffset = len;
    for ( auto _cname : cnamelist ) {
        buf.resize(buf.size() + 2 + 2 + 2 + 4 + 2 + (_cname.size() + 2));
        // Name
        uint16_t *_pname = (uint16_t *)(&buf[0] + _boffset);
        *_pname = _name_offset;
        _boffset += sizeof(uint16_t);

        // Type
        uint16_t *_ptype = (uint16_t *)(&buf[0] + _boffset);
        *_ptype = htons((uint16_t)dns_qtype_cname);
        _boffset += sizeof(uint16_t);

        // Class
        uint16_t *_pclass = (uint16_t *)(&buf[0] + _boffset);
        *_pclass = htons((uint16_t)dns_qclass_in);
        _boffset += sizeof(uint16_t);

        // TTL
        uint32_t *_pttl = (uint32_t *)(&buf[0] + _boffset);
        *_pttl = htonl(30 * 60);    // 30 mins
        _boffset += sizeof(uint32_t);

        // RLENGTH
        uint16_t *_prlen = (uint16_t *)(&buf[0] + _boffset);
        *_prlen = htons((uint16_t)_cname.size() + 2);
        _boffset += sizeof(uint16_t);

        // RDATA
        string _fcname;
        _dns_format_domain(_cname, _fcname);
        char *_prdata = (char *)(&buf[0] + _boffset);
        memcpy(_prdata, _fcname.c_str(), _fcname.size());
        _boffset += _fcname.size();
    }
}

void dns_get_a_records( const char *pkg, unsigned int len, string &qdomain, vector<uint32_t> &a_records )
{
    clnd_dns_package *_pheader = (clnd_dns_package *)pkg;
    const char *_pDomain = pkg + sizeof(clnd_dns_package);
    int _readsize = _dns_get_format_domain(_pDomain, pkg, qdomain);

    // Begin Answer Point
    const char *_pbuf = pkg + sizeof(clnd_dns_package) + _readsize + 2 + 2; // type + class
    uint16_t _an_count = _pheader->get_an_count();
    for ( uint16_t i = 0; i < _an_count; ++i ) {
        string _adomain;
        int _asize = _dns_get_format_domain(_pbuf, pkg, _adomain);
        _pbuf += _asize;

        uint16_t _type = ntohs(*(uint16_t *)_pbuf);
        _pbuf += sizeof(uint16_t);

        bool _need_a_records = ((dns_qtype)_type == dns_qtype_host);
        // skip class
        _pbuf += sizeof(uint16_t);
        // skip ttl
        _pbuf += sizeof(uint32_t);
        // length
        uint16_t _rlen = ntohs(*(uint16_t *)_pbuf);
        _pbuf += sizeof(uint16_t);

        if ( _need_a_records ) {
            uint32_t _a_rec = *(uint32_t *)_pbuf;
            a_records.push_back(_a_rec);
        }
        _pbuf += _rlen;
    }
}

// Check if is a query request
bool dns_is_query(const char *pkg, unsigned int len)
{
    clnd_dns_package *_pheader = (clnd_dns_package *)pkg;
    return _pheader->get_is_query_request();
}

#endif

// cleandns.dns.cpp
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/socket.cpp
// #include <execinfo.h>
#include <map>

// In No-Windows
#ifndef FAR
#define FAR
#endif

/* Translate Domain to IP Address */
char * network_domain_to_ip(const char * domain, char * output, unsigned int length)
{
    struct hostent FAR * _host_ent;
    struct in_addr _in_addr;
    char * _c_addr;
    
    memset(output, 0, length);
    
    _host_ent = gethostbyname(domain);
    if (_host_ent == NULL) return output;
    
    _c_addr = _host_ent->h_addr_list[0];
    if (_c_addr == NULL) return output;
    
    memmove(&_in_addr, _c_addr, 4);
    strcpy(output, inet_ntoa(_in_addr));
    
    return output;
}

/* Translate Domain to InAddr */
unsigned int network_domain_to_inaddr(const char * domain)
{
    /* Get the IP Address of the domain by invoking network_domain_to_ip */
    char _c_address[16];

    if (domain == NULL) return INADDR_ANY;
    if (network_domain_to_ip(domain, _c_address, 16)[0] == '\0') {
        // Try direct translate the domain
        return inet_addr(domain);
        //return (unsigned int)(-1L);
    }
    return inet_addr(_c_address);
}

// Translate the ip string to an InAddr
uint32_t network_ipstring_to_inaddr(const string &ipaddr)
{
    return inet_addr(ipaddr.c_str());
}

// Translate the InAddr to an Ip string
void network_inaddr_to_string(uint32_t inaddr, string &ipstring)
{
    char _ip_[16] = {0};
    sprintf( _ip_, "%u.%u.%u.%u",
        (inaddr >> (0 * 8)) & 0x00FF,
        (inaddr >> (1 * 8)) & 0x00FF,
        (inaddr >> (2 * 8)) & 0x00FF,
        (inaddr >> (3 * 8)) & 0x00FF 
    );
    ipstring = string(_ip_);
}

// Get localhost's computer name on LAN.
void network_get_localhost_name( string &hostname )
{
    char __hostname[256] = { 0 };
    if ( gethostname( __hostname, 256 ) == -1 ) {
        return;
    }
    hostname = string(__hostname);
}

// Convert the uint ip addr to human readable ip string.
void network_int_to_ipaddress( const u_int32_t ipaddr, string &ip )
{
    char _ip_[16] = {0};
    sprintf( _ip_, "%u.%u.%u.%u",
        (ipaddr >> (0 * 8)) & 0x00FF,
        (ipaddr >> (1 * 8)) & 0x00FF,
        (ipaddr >> (2 * 8)) & 0x00FF,
        (ipaddr >> (3 * 8)) & 0x00FF 
    );
    ip = string(_ip_);
}

// Get peer ipaddress and port from a specified socket handler.
void network_peer_info_from_socket( const SOCKET_T hSo, u_int32_t &ipaddr, u_int32_t &port )
{
    if ( SOCKET_NOT_VALIDATE(hSo) ) return;

    struct sockaddr_in _addr;
    socklen_t _addrLen = sizeof(_addr);
    memset( &_addr, 0, sizeof(_addr) );
    if ( 0 == getpeername( hSo, (struct sockaddr *)&_addr, &_addrLen ) )
    {
        port = ntohs(_addr.sin_port);
        ipaddr = _addr.sin_addr.s_addr;
    }
}

// Get current socket's port info
void network_sock_info_from_socket( const SOCKET_T hSo, uint32_t &port )
{
    if ( SOCKET_NOT_VALIDATE(hSo) ) return;

    struct sockaddr_in _addr;
    socklen_t _addrLen = sizeof(_addr);
    memset( &_addr, 0, sizeof(_addr) );
    if ( 0 == getsockname( hSo, (struct sockaddr *)&_addr, &_addrLen ) )
    {
        port = ntohs(_addr.sin_port);
    }
}

// Check the specified socket's status according to the option.
SOCKETSTATUE socket_check_status( SOCKET_T hSo, SOCKETOPT option, u_int32_t waitTime )
{
    if ( SOCKET_NOT_VALIDATE(hSo) ) return SO_INVALIDATE;
    fd_set _fs;
    FD_ZERO( &_fs );
    FD_SET( hSo, &_fs );

    int _ret = 0; struct timeval _tv = {(int32_t)waitTime / 1000, (int32_t)waitTime % 1000 * 1000};

    if ( option & SO_CHECK_READ ) {
        do {
            _ret = ::select( hSo + 1, &_fs, NULL, NULL, &_tv );
        } while ( _ret < 0 && errno == EINTR );
        if ( _ret > 0 ) {
            char _word;
            // the socket has received a close sig
            if ( ::recv( hSo, &_word, 1, MSG_PEEK ) <= 0 ) {
                return SO_INVALIDATE;
            }
            return SO_OK;
        }
        if ( _ret < 0 ) return SO_INVALIDATE;
    }

    if ( option & SO_CHECK_WRITE ){
        do {
            _ret = ::select( hSo + 1, NULL, &_fs, NULL, &_tv );
        } while ( _ret < 0 && errno == EINTR );
        if ( _ret > 0 ) return SO_OK;
        if ( _ret < 0 ) return SO_INVALIDATE;
    }
    return SO_IDLE;
}

// Set the linger time for a socket, I strong suggest not to change this value unless you 
// know what you are doing
bool socket_set_linger_time(SOCKET_T so, bool onoff, unsigned timeout)
{
	struct linger _sol = { (onoff ? 1 : 0), (int)timeout };
	return ( setsockopt(so, SOL_SOCKET, SO_LINGER, &_sol, sizeof(_sol)) == 0 );
}

sl_ip::sl_ip() {}
sl_ip::sl_ip(const sl_ip& rhs) : ip_(rhs.ip_) {}

// Conversition
sl_ip::sl_ip(const string &ipaddr) : ip_(ipaddr) {}
sl_ip::sl_ip(uint32_t ipaddr) {
    network_inaddr_to_string(ipaddr, ip_);
}
sl_ip::operator uint32_t() const {
    return network_ipstring_to_inaddr(ip_);
}
sl_ip::operator string&() { return ip_; }
sl_ip::operator string() const { return ip_; }
sl_ip::operator const string&() const { return ip_; }
sl_ip::operator const char *() const { return ip_.c_str(); }
const char * sl_ip::c_str() const { return ip_.c_str(); }
size_t sl_ip::size() const { return ip_.size(); }
// Cast operator
sl_ip & sl_ip::operator = (const string &ipaddr) {
    ip_ = ipaddr; 
    return *this;
}

sl_ip & sl_ip::operator = (uint32_t ipaddr) {
    network_inaddr_to_string(ipaddr, ip_);
    return *this;
}
bool sl_ip::operator == (const sl_ip& rhs) const
{
    return ip_ == rhs.ip_;
}
bool sl_ip::operator != (const sl_ip& rhs) const
{
    return ip_ != rhs.ip_;
}
bool sl_ip::operator <(const sl_ip& rhs) const
{
    return ntohl(*this) < ntohl(rhs);
}
bool sl_ip::operator >(const sl_ip& rhs) const
{
    return ntohl(*this) > ntohl(rhs);
}
bool sl_ip::operator <=(const sl_ip& rhs) const
{
    return ntohl(*this) <= ntohl(rhs);
}
bool sl_ip::operator >=(const sl_ip& rhs) const
{
    return ntohl(*this) >= ntohl(rhs);
}

ostream & operator << (ostream &os, const sl_ip & ip) {
    os << (const string&)ip;
    return os;
}

// Peer Info
void sl_peerinfo::parse_peerinfo_from_string(const string &format_string) {
    for ( size_t i = 0; i < format_string.size(); ++i ) {
        if ( format_string[i] != ':' ) continue;
        ip_ = format_string.substr(0, i);
        port_ = stoi(format_string.substr(i + 1), nullptr, 10);
        format_ = format_string;
        break;
    }
}
void sl_peerinfo::set_peerinfo(const string &ipaddress, uint16_t port) {
    ip_ = ipaddress;
    port_ = port;
    format_ = (const string &)ip_;
    format_ += ":";
    format_ += to_string(port_);
}
void sl_peerinfo::set_peerinfo(uint32_t inaddr, uint16_t port) {
    ip_ = inaddr;
    port_ = port;
    format_ = (const string &)ip_;
    format_ += ":";
    format_ += to_string(port_);
}

sl_peerinfo::sl_peerinfo(): format_("0.0.0.0:0"), ipaddress(ip_), port_number(port_) {}
sl_peerinfo::sl_peerinfo(uint32_t inaddr, uint16_t port) 
: ip_(inaddr), port_(port), ipaddress(ip_), port_number(port_) { 
    format_ = (const string &)ip_;
    format_ += ":";
    format_ += to_string(port_);
}
sl_peerinfo::sl_peerinfo(const string &format_string) : ipaddress(ip_), port_number(port_) {
    parse_peerinfo_from_string(format_string);
}
sl_peerinfo::sl_peerinfo(const string &ipstring, uint16_t port) 
: ip_(ipstring), port_(port), ipaddress(ip_), port_number(port_) {
    format_ = (const string &)ip_;
    format_ += ":";
    format_ += to_string(port_);
}
sl_peerinfo::sl_peerinfo(const sl_peerinfo& rhs)
: ip_(rhs.ip_), port_(rhs.port_), ipaddress(ip_), port_number(port_) { }

sl_peerinfo & sl_peerinfo::operator = (const sl_peerinfo& rhs) {
    ip_ = rhs.ip_;
    port_ = rhs.port_;
    format_ = rhs.format_;
    return *this;
}
sl_peerinfo & sl_peerinfo::operator = (const string &format_string) {
    parse_peerinfo_from_string(format_string);
    return *this;
}

sl_peerinfo::operator bool() const { return port_ > 0 && port_ <= 65535; }
sl_peerinfo::operator const string () const { 
    return format_;
}
sl_peerinfo::operator const char *() const {
    return format_.c_str();
}
const char * sl_peerinfo::c_str() const {
    return format_.c_str();
}
size_t sl_peerinfo::size() const {
    return format_.size();
}

const sl_peerinfo & sl_peerinfo::nan()
{
    static sl_peerinfo _nan(0, 0);
    return _nan;
}

ostream & operator << (ostream &os, const sl_peerinfo &peer) {
    os << peer.operator const string();
    return os;
}

sl_socket::sl_socket(bool iswrapper) : m_iswrapper(iswrapper), m_is_listening(false), m_socket(INVALIDATE_SOCKET) { }

// Virtual destructure
sl_socket::~sl_socket()
{
    if ( m_iswrapper == false ) {
        this->close();
    }
}
// Close the connection
void sl_socket::close()
{
    // // Debug to output the call stack
    // void *_callstack[128];
    // int _frames = backtrace(_callstack, 128);
    // backtrace_symbols_fd(_callstack, _frames, STDOUT_FILENO);

    if ( SOCKET_NOT_VALIDATE(m_socket) ) return;
    SL_NETWORK_CLOSESOCK(m_socket);
    m_socket = INVALIDATE_SOCKET;
    m_is_listening = false;
}

// Set current socket reusable or not
bool sl_socket::set_reusable( bool reusable )
{
    if ( m_socket == INVALIDATE_SOCKET ) return false;
    int _reused = reusable ? 1 : 0;
    return setsockopt( m_socket, SOL_SOCKET, SO_REUSEADDR,
        (const char *)&_reused, sizeof(int) ) != -1;
}

bool sl_socket::set_keepalive( bool keepalive )
{
    if ( m_socket == INVALIDATE_SOCKET ) return false;
    int _keepalive = keepalive ? 1 : 0;
    return setsockopt( m_socket, SOL_SOCKET, SO_KEEPALIVE, 
        (const char *)&_keepalive, sizeof(int) );
}

bool sl_socket::set_nonblocking(bool nonblocking) 
{
    if ( m_socket == INVALIDATE_SOCKET ) return false;
    unsigned long _u = (nonblocking ? 1 : 0);
    return SL_NETWORK_IOCTL_CALL(m_socket, FIONBIO, &_u) >= 0;
}

bool sl_socket::set_socketbufsize( unsigned int rmem, unsigned int wmem )
{
    if ( m_socket == INVALIDATE_SOCKET ) return false;
    if ( rmem != 0 ) {
        setsockopt(m_socket, SOL_SOCKET, SO_RCVBUF, 
                (char *)&rmem, sizeof(rmem));
    }
    if ( wmem != 0 ) {
        setsockopt(m_socket, SOL_SOCKET, SO_SNDBUF,
                (char *)&wmem, sizeof(wmem));
    }
    return true;
}

void sl_socket::dump()
{
    uint32_t _local_port, _peer_port, _peer_addr;
    network_peer_info_from_socket(m_socket, _peer_addr, _peer_port);
    network_sock_info_from_socket(m_socket, _local_port);
    int _type, _len = sizeof(int);
    getsockopt( m_socket, SOL_SOCKET, SO_TYPE, (char *)&_type, (socklen_t *)&_len);
    if ( _type == SOCK_STREAM ) {
        ldebug << "[SOCK_DUMP:TCP] from 127.0.0.1:";
    } else {
        ldebug << "[SOCK_DUMP:UDP] from 127.0.0.1:";
    }
    ldebug << _local_port << "=> " << sl_ip(_peer_addr).c_str() << ":" << _peer_port << lend;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/poller.cpp

sl_poller::sl_poller()
	:m_fd(-1), m_events(NULL), m_runloop_status(false), m_runloop_ret(0)
{
#if SL_TARGET_LINUX
	m_fd = epoll_create1(0);
	if ( m_fd == -1 ) {
		throw(std::runtime_error("Failed to create poller"));
	}
	m_events = (struct epoll_event *)calloc(
			CO_MAX_SO_EVENTS, sizeof(struct epoll_event));
#elif SL_TARGET_MAC
	m_fd = kqueue();
	if ( m_fd == -1 ) {
		throw(std::runtime_error("Failed to create poller"));
	}
	m_events = (struct kevent *)calloc(
			CO_MAX_SO_EVENTS, sizeof(struct kevent));
#endif
}

sl_poller::~sl_poller() {
	if ( m_fd != -1 ) close(m_fd);
	if ( m_events != NULL ) free(m_events);
	m_fd = -1;
	m_events = NULL;
}

bool sl_poller::bind_tcp_server( SOCKET_T so ) {
#if SL_TARGET_LINUX
	auto _tit = m_tcp_svr_map.find(so);
	bool _is_new_bind = (_tit == end(m_tcp_svr_map));
#endif
	m_tcp_svr_map[so] = true;
	int _retval = 0;
#if SL_TARGET_LINUX
	struct epoll_event _e;
	_e.data.fd = so;
	_e.events = EPOLLIN | EPOLLET;
	_retval = epoll_ctl( m_fd, EPOLL_CTL_ADD, so, &_e );
#elif SL_TARGET_MAC
	struct kevent _e;
	EV_SET(&_e, so, EVFILT_READ, EV_ADD, 0, 0, NULL);
	_retval = kevent(m_fd, &_e, 1, NULL, 0, NULL);
#endif
	if ( _retval == -1 ) {
		lerror << "failed to bind and monitor the tcp server socket: " << ::strerror(errno) << lend;
#if SL_TARGET_LINUX
		if ( _is_new_bind ) {
			m_tcp_svr_map.erase(so);
		}
#endif
	}
	return (_retval != -1);
}

bool sl_poller::bind_udp_server( SOCKET_T so ) {
#if SL_TARGET_LINUX
	auto _uit = m_udp_svr_map.find(so);
	bool _is_new_bind = (_uit == end(m_udp_svr_map));
#endif
	// Reset the flag
	m_udp_svr_map[so] = true;
	int _retval = 0;
#if SL_TARGET_LINUX
	struct epoll_event _e;
	_e.data.fd = so;
	_e.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	if ( _is_new_bind ) {
		_retval = epoll_ctl( m_fd, EPOLL_CTL_ADD, so, &_e );
	} else {
		_retval = epoll_ctl( m_fd, EPOLL_CTL_MOD, so, &_e );
	}
#elif SL_TARGET_MAC
	struct kevent _e;
	EV_SET(&_e, so, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, NULL);
	_retval = kevent(m_fd, &_e, 1, NULL, 0, NULL);
#endif
	if ( _retval == -1 ) {
		lerror << "failed to bind and monitor the udp server socket: " << ::strerror(errno) << lend;
#if SL_TARGET_LINUX
		if ( _is_new_bind ) {
			m_udp_svr_map.erase(so);
		}
#endif
	}
	return (_retval != -1);
}

size_t sl_poller::fetch_events( sl_poller::earray &events, unsigned int timedout ) {
	if ( m_fd == -1 ) return 0;
	int _count = 0;
#if SL_TARGET_LINUX
	_count = epoll_wait( m_fd, m_events, CO_MAX_SO_EVENTS, timedout );
#elif SL_TARGET_MAC
	struct timespec _ts = { timedout / 1000, timedout % 1000 * 1000 * 1000 };
	_count = kevent(m_fd, NULL, 0, m_events, CO_MAX_SO_EVENTS, &_ts);
#endif

	for ( int i = 0; i < _count; ++i ) {
#if SL_TARGET_LINUX
		struct epoll_event *_pe = m_events + i;
#elif SL_TARGET_MAC
		struct kevent *_pe = m_events + i;
#endif
		sl_event _e;
		_e.source = INVALIDATE_SOCKET;
		_e.socktype = IPPROTO_TCP;
		// Disconnected
#if SL_TARGET_LINUX
		if ( _pe->events & EPOLLERR || _pe->events & EPOLLHUP ) {
			_e.so = _pe->data.fd;
#elif SL_TARGET_MAC
		if ( _pe->flags & EV_EOF || _pe->flags & EV_ERROR ) {
			_e.so = _pe->ident;
#endif
			_e.event = SL_EVENT_FAILED;
			events.push_back(_e);
			continue;
		}
#if SL_TARGET_LINUX
		else if ( m_tcp_svr_map.find(_pe->data.fd) != m_tcp_svr_map.end() ) {
			_e.source = _pe->data.fd;
#elif SL_TARGET_MAC
		else if ( m_tcp_svr_map.find(_pe->ident) != m_tcp_svr_map.end()  ) {
			_e.source = _pe->ident;
#endif
			// Incoming
			while ( true ) {
				struct sockaddr _inaddr;
				socklen_t _inlen;
				SOCKET_T _inso = accept( _e.source, &_inaddr, &_inlen );
				if ( _inso == -1 ) {
					// No more incoming
					if ( errno == EAGAIN || errno == EWOULDBLOCK ) break;
					// On error
					_e.event = SL_EVENT_FAILED;
					_e.so = _e.source;
					events.push_back(_e);
					break;
				} else {
					// Set non-blocking
					unsigned long _u = 1;
					SL_NETWORK_IOCTL_CALL(_inso, FIONBIO, &_u);
					_e.event = SL_EVENT_ACCEPT;
					_e.so = _inso;
					events.push_back(_e);
					// Add to poll monitor
					// this->monitor_socket(_inso);
				}
			}
		}
#if SL_TARGET_LINUX
		else if ( m_udp_svr_map.find(_pe->data.fd) != m_udp_svr_map.end() ) {
			_e.so = _pe->data.fd;
#elif SL_TARGET_MAC
		else if ( m_udp_svr_map.find(_pe->ident) != m_udp_svr_map.end() ) {
			_e.so = _pe->ident;
#endif
			_e.source = _e.so;
			_e.socktype = IPPROTO_UDP;

			// Get the peer info, but remind the data in the queue.
			_e.event = SL_EVENT_DATA;
			socklen_t _l = sizeof(_e.address);
			::recvfrom( _e.so, NULL, 0, MSG_PEEK,
            	(struct sockaddr *)&_e.address, &_l);

			events.push_back(_e);
		}
		else {
			// R/W
#if SL_TARGET_LINUX
			_e.so = _pe->data.fd;
#elif SL_TARGET_MAC
			_e.so = _pe->ident;
#endif
			ldebug << "get event for socket: " << _e.so << lend;
			int _error = 0, _len = sizeof(int);
			getsockopt( _e.so, SOL_SOCKET, SO_ERROR, 
					(char *)&_error, (socklen_t *)&_len);
			if ( _error == 0 ) {
				// Check if is read or write
#if SL_TARGET_LINUX
				if ( _pe->events & EPOLLIN ) _e.event = SL_EVENT_DATA;
				else _e.event = SL_EVENT_WRITE;
#elif SL_TARGET_MAC
				if ( _pe->filter == EVFILT_READ ) _e.event = SL_EVENT_DATA;
				else _e.event = SL_EVENT_WRITE;
#endif
			} else {
				_e.event = SL_EVENT_FAILED;
			}

			ldebug << "did get r/w event for socket: " << _e.so << ", event: " << _e.event << lend;
			
            int _type;
			getsockopt( _e.so, SOL_SOCKET, SO_TYPE,
					(char *)&_type, (socklen_t *)&_len);
            if ( _type == SOCK_STREAM ) {
                _e.socktype = IPPROTO_TCP;
            } else {
                _e.socktype = IPPROTO_UDP;
            }
			events.push_back(_e);
		}
	}
	return events.size();
}

bool sl_poller::monitor_socket( SOCKET_T so, bool oneshot, SL_EVENT_ID eid, bool isreset ) {
	if ( m_fd == -1 ) return false;
#if SL_TARGET_LINUX

	// Socket must be nonblocking
	unsigned long _u = 1;
	SL_NETWORK_IOCTL_CALL(so, FIONBIO, &_u);

	struct epoll_event _ee;
	_ee.data.fd = so;
	_ee.events = EPOLLET;
	if ( eid & SL_EVENT_DATA ) _ee.events |= EPOLLIN;
	if ( eid & SL_EVENT_WRITE ) _ee.events |= EPOLLOUT;
	int _op = EPOLL_CTL_ADD;
	if ( oneshot ) {
		_ee.events |= EPOLLONESHOT;
		if ( isreset ) _op = EPOLL_CTL_MOD;
	}
	if ( -1 == epoll_ctl( m_fd, _op, so, &_ee ) ) {
		lerror << "failed to monitor the socket " << so << ": " << ::strerror(errno) << lend;
		return false;
	}
#elif SL_TARGET_MAC
	struct kevent _ke;
	unsigned short _flags = EV_ADD;
	if ( oneshot ) {
		_flags |= EV_ONESHOT;
	}
	if ( eid & SL_EVENT_DATA ) {
		EV_SET(&_ke, so, EVFILT_READ, _flags, 0, 0, NULL);
		if ( -1 == kevent(m_fd, &_ke, 1, NULL, 0, NULL) ) {
			lerror << "failed to monitor the socket for read " << so << ": " << ::strerror(errno) << lend;
			return false;
		}
	}
	if ( eid & SL_EVENT_WRITE ) {
		EV_SET(&_ke, so, EVFILT_WRITE, _flags, 0, 0, NULL);
		if ( -1 == kevent(m_fd, &_ke, 1, NULL, 0, NULL) ) {
			lerror << "failed to monitor the socket for write " << so << ": " << ::strerror(errno) << lend;
			return false;
		}
	}
#endif
	return true;
}

sl_poller &sl_poller::server() {
	static sl_poller _g_poller;
	return _g_poller;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/events.cpp

static const int __sl_bitorder[32] = {
    0, 1, 2, 6, 3, 11, 7, 16,
    4, 14, 12, 21, 8, 23, 17, 26,
    31, 5, 10, 15, 13, 20, 22, 25,
    30, 9, 19, 24, 29, 18, 28, 27
};

// Get the index of the last bit which is 1
#define SL_MACRO_LAST_1_INDEX(x)     (__sl_bitorder[((unsigned int)(((x) & -(x)) * 0x04653ADFU)) >> 27])

std::map<SOCKET_T, sl_handler_set> & _sl_event_map() {
    static std::map<SOCKET_T, sl_handler_set> _g_emap;
    return _g_emap;
}

mutex & _sl_event_mutex() {
    static mutex _egm;
    return _egm;
}

sl_handler_set sl_event_empty_handler()
{
    sl_handler_set _s;
    memset((void *)&_s, 0, sizeof(sl_handler_set));
    return _s;
}

// Bind the event handler set
void sl_event_bind_handler(SOCKET_T so, sl_handler_set&& hset)
{
    lock_guard<mutex> _(_sl_event_mutex());
    _sl_event_map()[so] = hset;
}
// Unbind the event handler set
void sl_event_unbind_handler(SOCKET_T so)
{
    lock_guard<mutex> _(_sl_event_mutex());
    _sl_event_map().erase(so);
}
// Search for the handler set
sl_handler_set sl_event_find_handler(SOCKET_T so)
{
    lock_guard<mutex> _(_sl_event_mutex());
    if ( _sl_event_map().find(so) == end(_sl_event_map()) ) {
        return sl_event_empty_handler();
    }
    return _sl_event_map()[so];
}
// Update the handler for specifial event
void sl_event_update_handler(SOCKET_T so, SL_EVENT_ID eid, sl_socket_event_handler&& h)
{
    if ( eid == 0 ) return;
    if ( eid & 0xFFFFFFE0 ) return; // Invalidate event flag
    lock_guard<mutex> _(_sl_event_mutex());
    auto _hit = _sl_event_map().find(so);
    if ( _hit == end(_sl_event_map()) ) return;
    (&_hit->second.on_accept)[SL_MACRO_LAST_1_INDEX(eid)] = h;
}

// sl_events member functions
sl_events::sl_events()
: timepiece_(10), rl_callback_(NULL), is_running_(false)
{
    lock_guard<mutex> _(running_lock_);
    this->_internal_start_runloop();
    this->_internal_add_worker();
}

sl_events::~sl_events()
{
    this->stop_run();
}

sl_events& sl_events::server()
{
    static sl_events _ge;
    return _ge;
}

void sl_events::_internal_start_runloop()
{
    // If already running, just return
    if ( is_running_ ) return;
    is_running_ = true;

    runloop_thread_ = new thread([this]{
        _internal_runloop();
    });
    this->_internal_add_worker();
    thread_pool_manager_ = new thread([this]{
        thread_agent _ta;

        while ( true ) {
            usleep(10000);
            if ( !this_thread_is_running() ) break;
            if ( events_pool_.size() > (thread_pool_.size() * 10) ) {
                this->_internal_add_worker();
            } else if ( events_pool_.size() < (thread_pool_.size() * 2) && thread_pool_.size() > 1 ) {
                this->_internal_remove_worker();
            }
        }
    });  
}

void sl_events::_internal_runloop()
{
    ldebug << "internal runloop thread id " << this_thread::get_id() << lend;
    thread_agent _ta;

    ldebug << "internal runloop started" << lend;
    while ( this_thread_is_running() ) {
        //ldebug << "runloop is still running" << lend;
        sl_poller::earray _event_list;
        uint32_t _tp = 10;
        sl_runloop_callback _fp = NULL;
        do {
            lock_guard<mutex> _(running_lock_);
            //ldebug << "copy the timpiece and callback" << lend;
            _tp = timepiece_;
            _fp = rl_callback_;
        } while(false);

        do {
            lock_guard<mutex> _(events_lock_);
            //ldebug << "copy the pending event list" << lend;
            _event_list = move(pending_events_);
        } while(false);

        // Force the fetch method to return immediately if have some pending events
        if ( _event_list.size() > 0 ) {
            _tp = 0;
        }

        //ldebug << "current pending events: " << _event_list.size() << lend;
        size_t _ecount = sl_poller::server().fetch_events(_event_list, _tp) + _event_list.size();
        if ( _ecount != 0 ) {
            //ldebug << "fetch some events, will process them" << lend;
            for ( auto &e : _event_list ) {
                events_pool_.notify_one(move(e));
            }
        }
        // Invoke the callback
        if ( _fp != NULL ) {
            _fp();
        }
    }

    linfo << "internal runloop will terminated" << lend;

    do {
        lock_guard<mutex> _(running_lock_);
        is_running_ = false;
    } while( false );
}

void sl_events::_internal_add_worker()
{
    thread *_worker = new thread([this](){
        _internal_worker();
    });
    thread_pool_.push_back(_worker);
}
void sl_events::_internal_remove_worker()
{
    if ( thread_pool_.size() == 0 ) return;
    thread *_last_worker = *thread_pool_.rbegin();
    thread_pool_.pop_back();
    if ( _last_worker->joinable() ) {
        safe_join_thread(_last_worker->get_id());
        _last_worker->join();
    }
    delete _last_worker;
}
void sl_events::_internal_worker()
{
    linfo << "strat a new worker thread " << this_thread::get_id() << lend;
    thread_agent _ta;

    sl_event _local_event;
    while ( this_thread_is_running() ) {
        if ( !events_pool_.wait_for(milliseconds(10), [&](sl_event&& e){
            _local_event = e;
        }) ) continue;
        SOCKET_T _s = ((_local_event.event == SL_EVENT_ACCEPT) && 
                        (_local_event.socktype == IPPROTO_TCP)) ? 
                        _local_event.source : _local_event.so;
        SL_EVENT_ID _e = ((_local_event.event == SL_EVENT_DATA) && 
                            (_local_event.so == _local_event.source) && 
                            (_local_event.socktype == IPPROTO_UDP)) ?
                            SL_EVENT_ACCEPT : _local_event.event;
        ldebug << "processing socket " << _s << " for event " << _e << lend;
        sl_handler_set _hs = sl_event_find_handler(_s);
        // Remove current event handler
        if ( _e != SL_EVENT_ACCEPT ) {
            sl_event_bind_handler(_local_event.so, move(sl_event_empty_handler()));
        }
        sl_socket_event_handler _seh = (&_hs.on_accept)[SL_MACRO_LAST_1_INDEX(_e)];
        if ( !_seh ) {
            lwarning << "No handler bind for event: " << 
                _e << " on socket " << _s << lend;
        } else {
            _seh(_local_event);
        }
    }
}

unsigned int sl_events::pending_socket_count()
{
    lock_guard<mutex> _(events_lock_);
    return events_pool_.size();
}

void sl_events::bind(sl_socket *pso, sl_handler_set&& hset) {
    if ( pso == NULL || SOCKET_NOT_VALIDATE(pso->m_socket) ) return;
    sl_event_bind_handler(pso->m_socket, move(hset));
}

void sl_events::unbind( sl_socket *pso ) {
    if ( pso == NULL || SOCKET_NOT_VALIDATE(pso->m_socket) ) return;
    sl_event_unbind_handler(pso->m_socket);
}
void sl_events::update_handler(sl_socket *pso, SL_EVENT_ID eid, sl_socket_event_handler&& h)
{
    if ( pso == NULL || SOCKET_NOT_VALIDATE(pso->m_socket) ) return;
    sl_event_update_handler(pso->m_socket, eid, move(h));
}
void sl_events::bind( SOCKET_T so, sl_handler_set&& hset )
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    sl_event_bind_handler(so, move(hset));
}
void sl_events::unbind( SOCKET_T so )
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    sl_event_unbind_handler(so);
}
void sl_events::update_handler( SOCKET_T so, SL_EVENT_ID eid, sl_socket_event_handler&& h)
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    sl_event_update_handler(so, eid, move(h));
}

bool sl_events::is_running() const
{
    lock_guard<mutex> _(running_lock_);
    return is_running_;
}

void sl_events::run(uint32_t timepiece, sl_runloop_callback cb)
{
    lock_guard<mutex> _(running_lock_);
    timepiece_ = timepiece;
    rl_callback_ = cb;

    this->_internal_start_runloop();
}

void sl_events::stop_run()
{
    do {
        lock_guard<mutex> _(running_lock_);
        if ( is_running_ == false ) return;
    } while ( false );

    if ( runloop_thread_->joinable() )  {
        safe_join_thread(runloop_thread_->get_id());
        runloop_thread_->join();
    }
    delete runloop_thread_;
    runloop_thread_ = NULL;

    // Close the thread pool manager
    if ( thread_pool_manager_->joinable() ) {
        safe_join_thread(thread_pool_manager_->get_id());
        thread_pool_manager_->join();
    }
    delete thread_pool_manager_;
    thread_pool_manager_ = NULL;

    // Close all worker in thread pool
    while ( thread_pool_.size() > 0 ) {
        this->_internal_remove_worker();
    }
}

void sl_events::add_event(sl_event && e)
{
    lock_guard<mutex> _(events_lock_);
    pending_events_.emplace_back(e);
}
void sl_events::add_tcpevent(SOCKET_T so, SL_EVENT_ID eid)
{
    lock_guard<mutex> _(events_lock_);
    sl_event _e;
    _e.so = so;
    _e.source = INVALIDATE_SOCKET;
    _e.event = eid;
    _e.socktype = IPPROTO_TCP;
    pending_events_.emplace_back(move(_e));
}
void sl_events::add_udpevent(SOCKET_T so, struct sockaddr_in addr, SL_EVENT_ID eid)
{
    lock_guard<mutex> _(events_lock_);
    sl_event _e;
    _e.so = so;
    _e.source = INVALIDATE_SOCKET;
    _e.event = eid;
    _e.socktype = IPPROTO_UDP;
    memcpy(&_e.address, &addr, sizeof(addr));
    pending_events_.emplace_back(move(_e));
}

// events.h

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/socks5.cpp

static bool sl_supported_method[3] = {false, false, false};

void sl_socks5_set_supported_method(sl_methods m) {
	if ( m > sl_method_userpwd ) return;
	sl_supported_method[m] = true;
}

string sl_socks5_get_string(const char *buffer, uint32_t length) {
	string _result = "";
	if ( length <= sizeof(uint8_t) ) return _result;
	uint8_t _string_size = buffer[0];
	if ( length < (sizeof(uint8_t) + _string_size) ) return _result;
	_result.append(buffer + 1, _string_size);
	return _result;
}

sl_methods sl_socks5_handshake_handler(SOCKET_T so) {
	sl_tcpsocket _wsrc(so);
	string _buffer;

	// Try to read the handshake package
	if ( (_wsrc.read_data(_buffer) & SO_READ_DONE) == 0 ) return sl_method_nomethod;
	sl_socks5_handshake_request *_req = (sl_socks5_handshake_request *)_buffer.data();
	sl_socks5_handshake_response _resp(sl_method_nomethod);

	const char *_methods = _buffer.data() + sizeof(sl_socks5_handshake_request);
	for ( uint8_t i = 0; i < _req->nmethods; ++i ) {
		if ( _methods[i] == sl_method_noauth ) {
			if ( sl_supported_method[sl_method_noauth] ) {
				_resp.method = sl_method_noauth;
				break;
			}
		} else if ( _methods[i] == sl_method_userpwd ) {
			if ( sl_supported_method[sl_method_userpwd] ) {
				_resp.method = sl_method_userpwd;
				break;
			}
		}
	}

	string _respdata((char *)&_resp, sizeof(_resp));
	_wsrc.write_data(_respdata);
	return (sl_methods)_resp.method;
}

bool sl_socks5_auth_by_username(SOCKET_T so, sl_auth_method auth) {
	sl_tcpsocket _wsrc(so);
	string _buffer;

	if ( (_wsrc.read_data(_buffer) & SO_READ_DONE) == 0 ) return false;
	if ( _buffer.data()[0] != 1 ) return false;		// version error

	const char *_b = _buffer.data() + 1;
	uint32_t _l = _buffer.size() - 1;
	string _username = sl_socks5_get_string(_b, _l);
	if ( _username.size() == 0 ) return false;
	_b += (_username.size() + sizeof(uint8_t));
	_l -= (_username.size() + sizeof(uint8_t));
	string _password = sl_socks5_get_string(_b, _l);
	if ( _password.size() == 0 ) return false;

	uint8_t _result = (auth(_username, _password) ? 0 : 1);
	char _resp[2] = {1, (char)_result};
	string _respdata(_resp, 2);
	_wsrc.write_data(_respdata);
	return _result == 0;
}

bool sl_socks5_get_connect_info(SOCKET_T so, string &addr, uint16_t& port) {
	sl_tcpsocket _wsrc(so);
	string _buffer;

	if ( (_wsrc.read_data(_buffer) & SO_READ_DONE) == 0 ) return false;
	sl_socks5_connect_request *_req = (sl_socks5_connect_request *)_buffer.data();
	sl_socks5_ipv4_response _resp(0, 0);

	for ( int _dummy = 0; _dummy == 0; _dummy++ ) {
		if ( _req->cmd != sl_socks5cmd_connect ) {
			_resp.rep = sl_socks5rep_notsupport;
			break;
		}
		const char *_data = _buffer.data() + sizeof(sl_socks5_connect_request);
		if ( _req->atyp == sl_socks5atyp_ipv4 ) {
			uint32_t _ip = *(uint32_t *)_data;
			network_int_to_ipaddress(_ip, addr);
			port = *(uint16_t *)(_data + sizeof(uint32_t));
			break;
		}
		if ( _req->atyp == sl_socks5atyp_dname ) {
			uint32_t _l = _buffer.size() - sizeof(sl_socks5_connect_request);
			addr = sl_socks5_get_string(_data, _l);
			if ( addr.size() == 0 ) {
				_resp.rep = sl_socks5rep_erroraddress;
				break;
			}
			port = *(uint16_t *)(_data + addr.size() + 1);
			break;
		}
		_resp.rep = sl_socks5rep_notsupport;
	}
	
	port = ntohs(port);
	return _resp.rep == sl_socks5rep_successed;
}

void sl_socks5_failed_connect_to_peer(SOCKET_T so, sl_socks5rep rep) {
	sl_tcpsocket _wsrc(so);

	sl_socks5_ipv4_response _resp(0, 0);
	_resp.rep = rep;
	string _respstring((char *)&_resp, sizeof(_resp));
	_wsrc.write_data(_respstring);
}
void sl_socks5_did_connect_to_peer(SOCKET_T so, uint32_t addr, uint16_t port) {
	sl_tcpsocket _wsrc(so);
	
	sl_socks5_ipv4_response _resp(addr, htons(port));
	string _respstring((char *)&_resp, sizeof(_resp));
	_wsrc.write_data(_respstring);
}

// socks5.cpp

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/raw.cpp
#include <errno.h>

#if SL_TARGET_LINUX
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#endif

void sl_socket_close(SOCKET_T so)
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    //sl_event_unbind_handler(so);
    ldebug << "the socket " << so << " will be unbind and closed" << lend;
    sl_events::server().unbind(so);
    close(so);
}

// TCP Methods
SOCKET_T sl_tcp_socket_init()
{
    SOCKET_T _so = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( SOCKET_NOT_VALIDATE(_so) ) {
        lerror << "failed to init a tcp socket: " << ::strerror( errno ) << lend;
        return _so;
    }
    // Set With TCP_NODELAY
    int flag = 1;
    if( setsockopt( _so, IPPROTO_TCP, 
        TCP_NODELAY, (const char *)&flag, sizeof(int) ) == -1 )
    {
        lerror << "failed to set the tcp socket(" << _so << ") to be TCP_NODELAY: " << ::strerror( errno ) << lend;
        SL_NETWORK_CLOSESOCK( _so );
        return INVALIDATE_SOCKET;
    }

    int _reused = 1;
    if ( setsockopt( _so, SOL_SOCKET, SO_REUSEADDR,
        (const char *)&_reused, sizeof(int) ) == -1)
    {
        lerror << "failed to set the tcp socket(" << _so << ") to be SO_REUSEADDR: " << ::strerror( errno ) << lend;
        SL_NETWORK_CLOSESOCK( _so );
        return INVALIDATE_SOCKET;
    }

    unsigned long _u = 1;
    if ( SL_NETWORK_IOCTL_CALL(_so, FIONBIO, &_u) < 0 ) 
    {
        lerror << "failed to set the tcp socket(" << _so << ") to be Non Blocking: " << ::strerror( errno ) << lend;
        SL_NETWORK_CLOSESOCK( _so );
        return INVALIDATE_SOCKET;
    }

    sl_events::server().bind(_so, sl_event_empty_handler());
    return _so;
}
bool sl_tcp_socket_connect(SOCKET_T tso, const sl_peerinfo& peer, sl_socket_event_handler callback)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return false;

    struct sockaddr_in _sock_addr;
    memset(&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_addr.s_addr = peer.ipaddress;
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(peer.port_number);

    // Update the on connect event callback
    sl_events::server().update_handler(tso, SL_EVENT_CONNECT, [callback](sl_event e){
        if ( e.event != SL_EVENT_CONNECT ) return;
        //callback(e.so);
        callback(e);
    });

    // Update the failed handler
    sl_events::server().update_handler(tso, SL_EVENT_FAILED, [callback](sl_event e){
        if ( e.event != SL_EVENT_FAILED ) return;
        //callback(INVALIDATE_SOCKET);
        callback(e);
    });

    if ( ::connect( tso, (struct sockaddr *)&_sock_addr, sizeof(_sock_addr)) == -1 ) {
        int _error = 0, _len = sizeof(_error);
        getsockopt( tso, SOL_SOCKET, SO_ERROR, (char *)&_error, (socklen_t *)&_len);
        if ( _error != 0 ) {
            lerror << "failed to connect to " << peer << " on tcp socket: " << tso << ", " << ::strerror( _error ) << lend;
            return false;
        } else {
            // Monitor the socket, the poller will invoke on_connect when the socket is connected or failed.
            ldebug << "monitor tcp socket " << tso << " for connecting" << lend;
            if ( !sl_poller::server().monitor_socket(tso, true, SL_EVENT_CONNECT) ) {
                //sl_events::server().add_tcpevent(tso, SL_EVENT_FAILED);
                return false;
            }
        }
    } else {
        // Add to next run loop to process the connect event.
        sl_events::server().add_tcpevent(tso, SL_EVENT_CONNECT);
    }
    return true;
}
bool sl_tcp_socket_connect(SOCKET_T tso, const vector<sl_ip> &iplist, uint16_t port, uint32_t index, sl_socket_event_handler callback) {
    bool _retval = true;
    do {
        ldebug << "iplist count: " << iplist.size() << ", current index: " << index << lend;
        if ( iplist.size() <= index ) return false;
        sl_peerinfo _pi((const string &)iplist[index], port);
        ldebug << "try to connect to " << _pi << ", this is the " << index << " item in iplist" << lend;
        _retval = sl_tcp_socket_connect(tso, sl_peerinfo((const string &)iplist[index], port), [iplist, port, index, callback](sl_event e) {
            if ( e.event == SL_EVENT_FAILED ) {
                // go to next
                if ( !sl_tcp_socket_connect(e.so, iplist, port, index + 1, callback) ) {
                    e.event = SL_EVENT_FAILED;
                    callback(e);
                }
            } else {
                // Connected
                callback(e);
            }
        });
        if ( _retval == false ) ++index;
    } while ( _retval == false );
    return _retval;
}
bool sl_tcp_socket_connect(SOCKET_T tso, const sl_peerinfo& socks5, const string& host, uint16_t port, sl_socket_event_handler callback)
{
    if ( socks5 ) {
        ldebug << "try to connect via a socks5 proxy: " << socks5 << lend;
        return ( sl_tcp_socket_connect(tso, socks5, [socks5, host, port, callback](sl_event e){
            if ( e.event == SL_EVENT_FAILED ) {
                lerror << "the socks5 proxy cannot be connected" << socks5 << lend;
                callback(e); return;
            }
            sl_socks5_noauth_request _req;
            // Exchange version info
            if (write(e.so, (char *)&_req, sizeof(_req)) < 0) {
                e.event = SL_EVENT_FAILED; callback(e); return;
            }

            sl_tcp_socket_monitor(e.so, [host, port, callback](sl_event e) {
                if ( e.event == SL_EVENT_FAILED ) {
                    callback(e); return;
                }
                string _pkg;
                if ( !sl_tcp_socket_read(e.so, _pkg) ) {
                    e.event = SL_EVENT_FAILED; callback(e); return;
                }
                const sl_socks5_handshake_response* _resp = (const sl_socks5_handshake_response *)_pkg.c_str();
                // This api is for no-auth proxy
                if ( _resp->ver != 0x05 && _resp->method != sl_method_noauth ) {
                    lerror << "unsupported authentication method" << lend;
                    e.event = SL_EVENT_FAILED; callback(e); return;
                }

                // Send the connect request
                // Establish a connection through the proxy server.
                uint8_t _buffer[256] = {0};
                // Socks info
                uint16_t _host_port = htons(port); // the port must be uint16

                /* Assemble the request packet */
                sl_socks5_connect_request _req;
                _req.atyp = sl_socks5atyp_dname;
                memcpy(_buffer, (char *)&_req, sizeof(_req));

                unsigned int _pos = sizeof(_req);
                _buffer[_pos] = (uint8_t)host.size();
                _pos += 1;
                memcpy(_buffer + _pos, host.data(), host.size());
                _pos += host.size();
                memcpy(_buffer + _pos, &_host_port, sizeof(_host_port));
                _pos += sizeof(_host_port);
                
                if (write(e.so, _buffer, _pos) == -1) {
                    e.event = SL_EVENT_FAILED; callback(e); return;
                }

                // Wait for the socks5 server's response
                sl_tcp_socket_monitor(e.so, [callback](sl_event e) {
                    if ( e.event == SL_EVENT_FAILED ) {
                        callback(e); return;
                    }
                    /*
                     * The maximum size of the protocol message we are waiting for is 10
                     * bytes -- VER[1], REP[1], RSV[1], ATYP[1], BND.ADDR[4] and
                     * BND.PORT[2]; see RFC 1928, section "6. Replies" for more details.
                     * Everything else is already a part of the data we are supposed to
                     * deliver to the requester. We know that BND.ADDR is exactly 4 bytes
                     * since as you can see below, we accept only ATYP == 1 which specifies
                     * that the IPv4 address is in a binary format.
                     */
                    string _pkg;
                    if (!sl_tcp_socket_read(e.so, _pkg)) {
                        e.event = SL_EVENT_FAILED; callback(e); return;
                    }
                    const sl_socks5_ipv4_response* _resp = (const sl_socks5_ipv4_response *)_pkg.c_str();

                    /* Check the server's version. */
                    if ( _resp->ver != 0x05 ) {
                        lerror << "Unsupported SOCKS version: " << _resp->ver << lend;
                        e.event = SL_EVENT_FAILED; callback(e); return;
                    }
                    if (_resp->rep != sl_socks5rep_successed) {
                        lerror << sl_socks5msg((sl_socks5rep)_resp->rep) << lend;
                        e.event = SL_EVENT_FAILED; callback(e); return;
                    }

                    /* Check ATYP */
                    if ( _resp->atyp != sl_socks5atyp_ipv4 ) {
                        lerror << "ssh-socks5-proxy: Address type not supported: " << _resp->atyp << lend;
                        e.event = SL_EVENT_FAILED; callback(e); return;
                    }
                    e.event = SL_EVENT_CONNECT; callback(e);
                }) ? void() : [&e, callback]() { e.event = SL_EVENT_FAILED; callback(e); }();
            }) ? void() : [&e, callback](){ e.event = SL_EVENT_FAILED; callback(e); }();
        }));
    } else {
        ldebug << "the socks5 is empty, try to connect to host(" << host << ") directly" << lend;
        sl_ip _host_ip(host);
        if ( (uint32_t)_host_ip == (uint32_t)-1 ) {
            ldebug << "the host(" << host << ") is not an IP address, try to resolve first" << lend;
            // This is a domain
            sl_async_gethostname(host, [tso, host, port, callback](const vector<sl_ip> &iplist){
                if ( iplist.size() == 0 || ((uint32_t)iplist[0] == (uint32_t)-1) ) {
                    // Error
                    lerror << "failed to resolv " << host << lend;
                    sl_event _e;
                    _e.so = tso;
                    _e.event = SL_EVENT_FAILED;
                    callback(_e);
                } else {
                    ldebug << "resolvd the host " << host << ", trying to connect via tcp socket" << lend;
                    if ( !sl_tcp_socket_connect(tso, iplist, port, 0, callback) ) {
                        lerror << "failed to connect to the host(" << host << ")" << lend;
                        sl_event _e;
                        _e.so = tso;
                        _e.event = SL_EVENT_FAILED;
                        callback(_e);
                    }
                }
            });
            return true;
        }
        return sl_tcp_socket_connect(tso, sl_peerinfo(host, port), callback);
    }
}
bool sl_tcp_socket_send(SOCKET_T tso, const string &pkg)
{
    if ( pkg.size() == 0 ) return false;
    if ( SOCKET_NOT_VALIDATE(tso) ) return false;

    ldebug << "will write data(l:" << pkg.size() << ") to tcp socket: " << tso << lend;
    int _lastSent = 0;

    unsigned int _length = pkg.size();
    const char *_data = pkg.c_str();

    while ( _length > 0 )
    {
        _lastSent = ::send( tso, _data, 
            _length, 0 | SL_NETWORK_NOSIGNAL );
        if( _lastSent <= 0 ) {
            if ( ENOBUFS == errno || EAGAIN == errno ) {
                // try to increase the write buffer and then retry
                uint32_t _wmem = 0, _lmem = 0;
                getsockopt(tso, SOL_SOCKET, SO_SNDBUF, (char *)&_wmem, &_lmem);
                _wmem *= 2; // double the buffer
                setsockopt(tso, SOL_SOCKET, SO_SNDBUF, (char *)&_wmem, _lmem);
            } else {
                // Failed to send
                lerror << "failed to send data on tcp socket: " << tso << ", err(" << errno << "): " << ::strerror(errno) << lend;
                return false;
            }
        } else {
            _data += _lastSent;
            _length -= _lastSent;
        }
    }
    return true;
}
bool sl_tcp_socket_monitor(SOCKET_T tso, sl_socket_event_handler callback, bool new_incoming)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return false;
    if ( !callback ) return false;
    auto _fp = [callback](sl_event e) {
        if ( e.event != SL_EVENT_READ ) return;
        //callback(e.so);
        callback(e);
    };
    sl_events::server().update_handler(tso, SL_EVENT_READ, _fp);

    // Update the failed callback
    sl_events::server().update_handler(tso, SL_EVENT_FAILED, [callback](sl_event e){
        if ( e.event != SL_EVENT_FAILED ) return;
        //callback(INVALIDATE_SOCKET);
        callback(e);
    });

    return sl_poller::server().monitor_socket(tso, true, SL_EVENT_DEFAULT, !new_incoming);
}
bool sl_tcp_socket_read(SOCKET_T tso, string& buffer, size_t max_buffer_size)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return false;
    
    // Socket must be nonblocking
    buffer.clear();
    buffer.resize(max_buffer_size);
    size_t _received = 0;
    size_t _leftspace = max_buffer_size;

    do {
        int _retCode = ::recv(tso, &buffer[0] + _received, _leftspace, 0 );
        if ( _retCode < 0 ) {
            int _error = 0, _len = sizeof(int);
            getsockopt( tso, SOL_SOCKET, SO_ERROR,
                    (char *)&_error, (socklen_t *)&_len);
            if ( _error == EINTR ) continue;    // signal 7, retry
            if ( _error == EAGAIN ) {
                // No more data on a non-blocking socket
                buffer.resize(_received);
                return true;
            }
            // Other error
            buffer.resize(0);
            lerror << "failed to receive data on tcp socket: " << tso << ", " << ::strerror( _error ) << lend;
            return false;
        } else if ( _retCode == 0 ) {
            // Peer Close
            buffer.resize(0);
            return false;
        } else {
            _received += _retCode;
            _leftspace -= _retCode;
            if ( _leftspace > 0 ) {
                // Unfull
                buffer.resize(_retCode);
                return true;
            } else {
                // The buffer is full, try to double the buffer and try again
                max_buffer_size *= 2;
                _leftspace = max_buffer_size - _received;
                buffer.resize(max_buffer_size);
            }
        }
    } while ( true );
    return true;
}
bool sl_tcp_socket_listen(SOCKET_T tso, const sl_peerinfo& bind_port, sl_socket_event_handler accept_callback)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return false;
    struct sockaddr_in _sock_addr;
    memset((char *)&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(bind_port.port_number);
    _sock_addr.sin_addr.s_addr = bind_port.ipaddress;

    sl_events::server().update_handler(tso, SL_EVENT_ACCEPT, [accept_callback](sl_event e) {
        if ( e.event != SL_EVENT_ACCEPT ) {
            lerror << "the incoming socket event is not an accept event." << lend;
            return;
        }
        // Set With TCP_NODELAY
        int flag = 1;
        if( setsockopt( e.so, IPPROTO_TCP, 
            TCP_NODELAY, (const char *)&flag, sizeof(int) ) == -1 )
        {
            lerror << "failed to set the tcp socket(" << e.so << ") to be TCP_NODELAY: " << ::strerror( errno ) << lend;
            SL_NETWORK_CLOSESOCK( e.so );
            return;
        }

        int _reused = 1;
        if ( setsockopt( e.so, SOL_SOCKET, SO_REUSEADDR,
            (const char *)&_reused, sizeof(int) ) == -1)
        {
            lerror << "failed to set the tcp socket(" << e.so << ") to be SO_REUSEADDR: " << ::strerror( errno ) << lend;
            SL_NETWORK_CLOSESOCK( e.so );
            return;
        }

        unsigned long _u = 1;
        if ( SL_NETWORK_IOCTL_CALL(e.so, FIONBIO, &_u) < 0 ) 
        {
            lerror << "failed to set the tcp socket(" << e.so << ") to be Non Blocking: " << ::strerror( errno ) << lend;
            SL_NETWORK_CLOSESOCK( e.so );
            return;
        }

        sl_events::server().bind(e.so, sl_event_empty_handler());
        accept_callback(e);
    });

    if ( ::bind(tso, (struct sockaddr *)&_sock_addr, sizeof(_sock_addr)) == -1 ) {
        lerror << "failed to listen tcp on " << bind_port << ": " << ::strerror( errno ) << lend;
        return false;
    }
    if ( -1 == ::listen(tso, 1024) ) {
        lerror << "failed to listen tcp on " << bind_port << ": " << ::strerror( errno ) << lend;
        return false;
    }
    linfo << "start to listening tcp on " << bind_port << lend;
    if ( !sl_poller::server().bind_tcp_server(tso) ) {
        return false;
    }
    return true;
}
sl_peerinfo sl_tcp_get_original_dest(SOCKET_T tso)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return sl_peerinfo(INADDR_ANY, 0);
#if SL_TARGET_LINUX
    struct sockaddr_in _dest_addr;
    socklen_t _socklen = sizeof(_dest_addr);
    int _error = getsockopt( tso, SOL_IP, SO_ORIGINAL_DST, &_dest_addr, &_socklen );
    if ( _error ) return sl_peerinfo(INADDR_ANY, 0);
    return sl_peerinfo(_dest_addr.sin_addr.s_addr, ntohs(_dest_addr.sin_port));
#else
    return sl_peerinfo(INADDR_ANY, 0);
#endif
}
// UDP Methods
SOCKET_T sl_udp_socket_init(const sl_peerinfo& bind_addr)
{
    SOCKET_T _so = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( SOCKET_NOT_VALIDATE(_so) ) {
        lerror << "failed to init a udp socket: " << ::strerror( errno ) << lend;
        return _so;
    }
    // Bind to 0, so we can get the port number by getsockname
    struct sockaddr_in _usin = {};
    _usin.sin_family = AF_INET;
    _usin.sin_addr.s_addr = bind_addr.ipaddress;
    _usin.sin_port = htons(bind_addr.port_number);
    if ( -1 == ::bind(_so, (struct sockaddr *)&_usin, sizeof(_usin)) ) {
        lerror << "failed to create a udp socket and bind to " << bind_addr << lend;
        SL_NETWORK_CLOSESOCK(_so);
        return INVALIDATE_SOCKET;
    }

    // Try to set the udp socket as nonblocking
    unsigned long _u = 1;
    SL_NETWORK_IOCTL_CALL(_so, FIONBIO, &_u);

    // Bind the empty handler set
    //sl_event_bind_handler(_so, sl_event_empty_handler());
    sl_events::server().bind(_so, sl_event_empty_handler());
    return _so;
}

bool sl_udp_socket_send(SOCKET_T uso, const string &pkg, const sl_peerinfo& peer)
{
    if ( pkg.size() == 0 ) return false;
    if ( SOCKET_NOT_VALIDATE(uso) ) return false;

    int _allSent = 0;
    int _lastSent = 0;
    struct sockaddr_in _sock_addr = {};
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(peer.port_number);
    _sock_addr.sin_addr.s_addr = (uint32_t)peer.ipaddress;

    uint32_t _length = pkg.size();
    const char *_data = pkg.c_str();

    // Get the local port for debug usage.
    uint32_t _lport;
    network_sock_info_from_socket(uso, _lport);

    while ( (unsigned int)_allSent < _length )
    {
        _lastSent = ::sendto(uso, _data + _allSent, 
            (_length - (unsigned int)_allSent), 0, 
            (struct sockaddr *)&_sock_addr, sizeof(_sock_addr));
        if ( _lastSent < 0 ) {
            lerror << "failed to write data via udp socket(" << uso << ", 127.0.0.1:" << _lport << "): " << ::strerror(errno) << lend;
            return false;
        }
        _allSent += _lastSent;
    }
    return true;
}
bool sl_udp_socket_monitor(SOCKET_T uso, const sl_peerinfo& peer, sl_socket_event_handler callback)
{
    if ( SOCKET_NOT_VALIDATE(uso) ) return false;
    if ( !callback ) return false;

    sl_events::server().update_handler(uso, SL_EVENT_READ, [peer, callback](sl_event e) {
        if ( e.event != SL_EVENT_READ ) return;
        ldebug << "udp socket " << e.so << " did get read event callback, which means has incoming data" << lend;
        if ( peer ) {
            e.address.sin_family = AF_INET;
            e.address.sin_port = htons(peer.port_number);
            e.address.sin_addr.s_addr = (uint32_t)peer.ipaddress;
        }
        //callback(e.so, e.address);
        callback(e);
    });

    sl_events::server().update_handler(uso, SL_EVENT_FAILED, [peer, callback](sl_event e){
        if ( e.event != SL_EVENT_FAILED ) return;
        //callback(INVALIDATE_SOCKET, e.address);
        if ( peer ) {
            e.address.sin_family = AF_INET;
            e.address.sin_port = htons(peer.port_number);
            e.address.sin_addr.s_addr = (uint32_t)peer.ipaddress;
        }
        callback(e);
    });
    ldebug << "did update the handler for udp socket " << uso << " on SL_EVENT_READ(2) and SL_EVENT_FAILED(4)" << lend;
    return sl_poller::server().monitor_socket(uso, true, SL_EVENT_DEFAULT);
}
bool sl_udp_socket_read(SOCKET_T uso, struct sockaddr_in addr, string& buffer, size_t max_buffer_size)
{
    if ( SOCKET_NOT_VALIDATE(uso) ) return false;

    sl_peerinfo _pi(addr.sin_addr.s_addr, ntohs(addr.sin_port));
    ldebug << "udp socket " << uso << " tring to read data from " << _pi << lend;
    buffer.clear();
    buffer.resize(max_buffer_size);

    do {
        unsigned _so_len = sizeof(addr);
        int _retCode = ::recvfrom( uso, &buffer[0], max_buffer_size, 0,
            (struct sockaddr *)&addr, &_so_len);
        if ( _retCode < 0 ) {
            int _error = 0, _len = sizeof(int);
            getsockopt( uso, SOL_SOCKET, SO_ERROR,
                    (char *)&_error, (socklen_t *)&_len);
            if ( _error == EINTR ) continue;    // signal 7, retry
            // Other error
            lerror << "failed to receive data on udp socket: " << uso << ", " << ::strerror( _error ) << lend;
            buffer.resize(0);
            return false;
        } else if ( _retCode == 0 ) {
            // Peer Close
            buffer.resize(0);
            return false;
        } else {
            buffer.resize(_retCode);
            return true;
        }
    } while ( true );
    return true;
}

bool sl_udp_socket_listen(SOCKET_T uso, sl_socket_event_handler accept_callback)
{
    if ( SOCKET_NOT_VALIDATE(uso) ) return false;

    sl_events::server().update_handler(uso, SL_EVENT_ACCEPT, [accept_callback](sl_event e) {
        if ( e.event != SL_EVENT_DATA ) {
            lerror << "the incoming socket event is not an accept event." << lend;
            return;
        }
        accept_callback(e);
        bool _ret = false;
        do{
            _ret = sl_poller::server().bind_udp_server(e.so);
            if ( _ret == false ) {
                usleep(1000000);
            }
        } while( _ret == false );
    });

    uint32_t _port;
    network_sock_info_from_socket(uso, _port);
    linfo << "start to listening udp on " << _port << lend;
    sl_poller::server().bind_udp_server(uso);
    return true;
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

// Global DNS Server List
vector<sl_peerinfo> _resolv_list;
void __sl_async_gethostnmae_udp(const string&& query_pkg, size_t use_index, async_dns_handler fp);
void __sl_async_gethostnmae_tcp(const string&& query_pkg, size_t use_index, async_dns_handler fp);

void __sl_async_gethostnmae_udp(const string&& query_pkg, size_t use_index, async_dns_handler fp)
{
    // No other validate resolve ip in the list, return the 255.255.255.255
    if ( _resolv_list.size() == use_index ) {
        lwarning << "no more nameserver validated" << lend;
        fp( {sl_ip((uint32_t)-1)} );
        return;
    }

    // Create a new udp socket and send the query package.
    SOCKET_T _uso = sl_udp_socket_init();
    string _domain;
    dns_get_domain(query_pkg.c_str(), query_pkg.size(), _domain);
    ldebug << "initialize a udp socket " << _uso << " to query domain: " << _domain << lend;
    if ( !sl_udp_socket_send(_uso, query_pkg, _resolv_list[use_index]) ) {
        lerror << "failed to send dns query package to " << _resolv_list[use_index] << lend;
        // Failed to send( unable to access the server );
        sl_socket_close(_uso);
        // Go next server
        __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
        return;
    }

    // Monitor for the response data
    sl_udp_socket_monitor(_uso, _resolv_list[use_index], [&query_pkg, use_index, fp](sl_event e) {
        // Current server has closed the socket
        if ( e.event == SL_EVENT_FAILED ) {
            lerror << "failed to get response from " << _resolv_list[use_index] << " for dns query." << lend;
            sl_socket_close(e.so);
            __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
            return;
        }

        // Read the incoming package
        string _incoming_pkg;
        if (!sl_udp_socket_read(e.so, e.address, _incoming_pkg)) {
            lerror << "failed to read data from udp socket for dns query." << lend;
            sl_socket_close(e.so);
            __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
            return;
        }
        sl_socket_close(e.so);

        const clnd_dns_package *_pheader = (const clnd_dns_package *)_incoming_pkg.c_str();
        if ( _pheader->get_resp_code() == dns_rcode_noerr ) {
            vector<uint32_t> _a_recs;
            string _qdomain;
            dns_get_a_records(_incoming_pkg.c_str(), _incoming_pkg.size(), _qdomain, _a_recs);
            vector<sl_ip> _retval;
            for ( auto _a : _a_recs ) {
                _retval.push_back(sl_ip(_a));
            }
            fp( _retval );
        } else if ( _pheader->get_is_truncation() ) {
            // TRUNC flag get, try to use tcp
            __sl_async_gethostnmae_tcp(move(query_pkg), use_index, fp);
        } else {
            __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
        }
    }) ? void() : [&query_pkg, use_index, fp, _uso](){
        lerror << "failed to monitor on " << _uso << lend;
        sl_socket_close(_uso);
        // Go next server
        __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
        return;
    }();
}
void __sl_async_gethostnmae_tcp(const string&& query_pkg, size_t use_index, async_dns_handler fp)
{
    SOCKET_T _tso = sl_tcp_socket_init();
    if ( SOCKET_NOT_VALIDATE(_tso) ) {
        // No enough file handler
        __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
        return;
    }

    sl_tcp_socket_connect(_tso, _resolv_list[use_index], [&query_pkg, use_index, fp](sl_event e) {
        if ( e.event == SL_EVENT_FAILED ) {
            // Server not support tcp
            //sl_socket_close(_tso);
            sl_socket_close(e.so);
            __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
            return;
        }
        string _tpkg;
        dns_generate_tcp_redirect_package(move(query_pkg), _tpkg);
        if ( !sl_tcp_socket_send(e.so, _tpkg) ) {
            // Failed to send
            sl_socket_close(e.so);
            __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
            return;
        }
        sl_tcp_socket_monitor(e.so, [&query_pkg, use_index, fp](sl_event e) {
            if ( e.event == SL_EVENT_FAILED ) {
                // Peer closed
                sl_socket_close(e.so);
                __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
                return;
            }

            // Read incoming
            string _tcp_incoming_pkg;
            if ( !sl_tcp_socket_read(e.so, _tcp_incoming_pkg) ) {
                sl_socket_close(e.so);
                __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
                return;
            }
            sl_socket_close(e.so);

            string _incoming_pkg;
            dns_generate_udp_response_package_from_tcp(_tcp_incoming_pkg, _incoming_pkg);
            const clnd_dns_package *_pheader = (const clnd_dns_package *)_incoming_pkg.c_str();
            if ( _pheader->get_resp_code() == dns_rcode_noerr ) {
                vector<uint32_t> _a_recs;
                string _qdomain;
                dns_get_a_records(_incoming_pkg.c_str(), _incoming_pkg.size(), _qdomain, _a_recs);
                vector<sl_ip> _retval;
                for ( auto _a : _a_recs ) {
                    _retval.push_back(sl_ip(_a));
                }
                fp( _retval );
            } else {
                __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
            }
        }) ? void() : [&query_pkg, use_index, fp, e](){
            lerror << "failed to monitor on " << e.so << lend;
            sl_socket_close(e.so);
            __sl_async_gethostnmae_udp(move(query_pkg), use_index + 1, fp);
        }();
    });
}
void sl_async_gethostname(const string& host, async_dns_handler fp)
{
    if ( _resolv_list.size() == 0 ) {
        res_init();
        for ( int i = 0; i < _res.nscount; ++i ) {
            sl_peerinfo _pi(
                _res.nsaddr_list[i].sin_addr.s_addr, 
                ntohs(_res.nsaddr_list[i].sin_port)
                );
            _resolv_list.push_back(_pi);
            ldebug << "resolv get dns: " << _pi << lend;
        }
    }
    string _qpkg;
    dns_generate_query_package(host, _qpkg);
    __sl_async_gethostnmae_udp(move(_qpkg), 0, fp);
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/tcpsocket.cpp
#include <memory>
#if SL_TARGET_LINUX
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#endif


sl_tcpsocket::sl_tcpsocket(bool iswrapper) 
    : sl_socket(iswrapper),
	m_is_connected_to_proxy(false)
{
    // Nothing
}
sl_tcpsocket::sl_tcpsocket(SOCKET_T so, bool iswrapper)
	: sl_socket(iswrapper),
	m_is_connected_to_proxy(false)
{
    m_socket = so;
}
sl_tcpsocket::~sl_tcpsocket()
{
}

// Connect to peer
bool sl_tcpsocket::_internal_connect( uint32_t inaddr, uint32_t port, uint32_t timeout ) 
{
    // Create Socket Handle
    m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // SOCKET_T hSo = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) {
        return false;
    }
    
    // Set With TCP_NODELAY
    int flag = 1;
    if( setsockopt( m_socket, IPPROTO_TCP, 
        TCP_NODELAY, (const char *)&flag, sizeof(int) ) == -1 )
    {
        SL_NETWORK_CLOSESOCK( m_socket );
        return false;
    }

    struct sockaddr_in _sock_addr; 
    memset( &_sock_addr, 0, sizeof(_sock_addr) );
    _sock_addr.sin_addr.s_addr = inaddr;
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(port);

    // Async Socket Connecting
    unsigned long _u = 1;
    SL_NETWORK_IOCTL_CALL(m_socket, FIONBIO, &_u);

    // Connect
    if ( ::connect( m_socket, (struct sockaddr *)&_sock_addr, 
            sizeof(_sock_addr) ) == -1 )
    {
        struct timeval _tm = { timeout / 1000, 
            static_cast<int>((timeout % 1000) * 1000) };
        fd_set _fs;
        int _error = 0, len = sizeof(_error);
        FD_ZERO( &_fs );
        FD_SET( m_socket, &_fs );

        // Wait until timeout
        do {
            _error = ::select( m_socket + 1, NULL, &_fs, NULL, &_tm );
        } while( _error < 0 && errno == EINTR );

        // _error > 0 means writable, then check if has any error.
        if ( _error > 0 ) {
            getsockopt( m_socket, SOL_SOCKET, SO_ERROR, 
                (char *)&_error, (socklen_t *)&len);
            if ( _error != 0 ) {
                // Failed to connect
                SL_NETWORK_CLOSESOCK( m_socket );
                m_socket = INVALIDATE_SOCKET;
                return false;
            }
        } else {
            // Failed to connect
            SL_NETWORK_CLOSESOCK( m_socket );
            m_socket = INVALIDATE_SOCKET;
            return false;
        }
    }
    // Reset Socket Statue
    _u = 0;
    SL_NETWORK_IOCTL_CALL(m_socket, FIONBIO, &_u);
    this->set_reusable();
    return true;
}

bool sl_tcpsocket::_internal_connect( const string &ipaddr, uint32_t port, uint32_t timeout )
{
    if ( ipaddr.size() == 0 || port == 0 || port >= 65535 ) return false;
    
    const char *_addr = ipaddr.c_str();

    // Try to nslookup the host
    unsigned int _in_addr = network_domain_to_inaddr( _addr );
    if ( _in_addr == (unsigned int)(-1) ) {
        return false;
    }

    return _internal_connect(_in_addr, port, timeout);
}

bool sl_tcpsocket::setup_proxy( const string &socks5_addr, uint32_t socks5_port )
{
    // Build a connection to the proxy server
    if ( ! this->_internal_connect( socks5_addr, socks5_port ) ) {
		fprintf(stderr, "failed to connect to the socks5 proxy server\n");
		return false;
	}
	
	sl_socks5_noauth_request _req;
    // Exchange version info
    if (write(m_socket, (char *)&_req, sizeof(_req)) < 0) {
        this->close();
        return false;
    }

	sl_socks5_handshake_response _resp;
    if (read(m_socket, (char *)&_resp, sizeof(_resp)) == -1) {
        this->close();
        return false;
    }

	// This api is for no-auth proxy
	if ( _resp.ver != 0x05 && _resp.method != sl_method_noauth ) {
		fprintf(stderr, "unsupported authentication method\n");
        this->close();
        return false;
    }

    // Now we has connected to the proxy server.
    m_is_connected_to_proxy = true;
    return true;
}

bool sl_tcpsocket::setup_proxy(
		const string &socks5_addr, uint32_t socks5_port,
		const string &username, const string &password) 
{
	// Connect to socks 5 proxy
	if ( ! this->_internal_connect( socks5_addr, socks5_port ) ) {
		fprintf(stderr, "failed to connect to the socks5 proxy server\n");
		return false;
	}

	sl_socks5_userpwd_request _req;
	char *_buf = (char *)malloc(sizeof(_req) + username.size() + password.size() + 2);
	memcpy(_buf, (char *)&_req, sizeof(_req));
	int _index = sizeof(_req);
	_buf[_index] = (uint8_t)username.size();
	_index += 1;
	memcpy(_buf + _index, username.data(), username.size());
	_index += username.size();
	_buf[_index] = (uint8_t)password.size();
	_index += 1;
	memcpy(_buf + _index, password.data(), password.size());
	_index += password.size();

	// Send handshake package
	if (write(m_socket, _buf, _index) < 0) {
		this->close();
		return false;
	}
	free(_buf);

	sl_socks5_handshake_response _resp;
	if (read(m_socket, (char *)&_resp, sizeof(_resp)) == -1 ) {
		this->close();
		return false;
	}

	// Check if server support username/password
	if ( _resp.ver != 0x05 && _resp.method != sl_method_userpwd ) {
		fprintf(stderr, "unspported username/password authentication method\n");
		this->close();
		return false;
	}

	// Now we has connected to the proxy server.
	m_is_connected_to_proxy = true;
	return true;
}
bool sl_tcpsocket::connect( const uint32_t inaddr, uint32_t port, uint32_t timeout )
{
    if ( m_is_connected_to_proxy == false ) {
        return this->_internal_connect( inaddr, port, timeout );
    } else {
        // Establish a connection through the proxy server.
        u_int8_t _buffer[256] = {0};
        // Socks info
        u_int16_t _host_port = htons((u_int16_t)port); // the port must be uint16

        /* Assemble the request packet */
        sl_socks5_connect_request _req;
        _req.atyp = sl_socks5atyp_ipv4;
        memcpy(_buffer, (char *)&_req, sizeof(_req));

        unsigned int _pos = sizeof(_req);
        _buffer[_pos] = sizeof(inaddr);
        _pos += 1;
        //*((uint32_t *)(_buffer + _pos)) = inaddr;
        memcpy(_buffer + _pos, &inaddr, sizeof(inaddr));
        _pos += sizeof(inaddr);
        memcpy(_buffer + _pos, &_host_port, sizeof(_host_port));
        _pos += sizeof(_host_port);
        
        if (write(m_socket, _buffer, _pos) == -1) {
            return false;
        }

        /*
         * The maximum size of the protocol message we are waiting for is 10
         * bytes -- VER[1], REP[1], RSV[1], ATYP[1], BND.ADDR[4] and
         * BND.PORT[2]; see RFC 1928, section "6. Replies" for more details.
         * Everything else is already a part of the data we are supposed to
         * deliver to the requester. We know that BND.ADDR is exactly 4 bytes
         * since as you can see below, we accept only ATYP == 1 which specifies
         * that the IPv4 address is in a binary format.
         */
        sl_socks5_ipv4_response _resp;
        if (read(m_socket, (char *)&_resp, sizeof(_resp)) == -1) {
            return false;
        }

        /* Check the server's version. */
        if ( _resp.ver != 0x05 ) {
            (void)fprintf(stderr, "Unsupported SOCKS version: %x\n", _resp.ver);
            return false;
        }
        if (_resp.rep != sl_socks5rep_successed) {
            fprintf(stderr, "%s\n", sl_socks5msg((sl_socks5rep)_resp.rep));
            return false;
        }

        /* Check ATYP */
        if ( _resp.atyp != sl_socks5atyp_ipv4 ) {
            fprintf(stderr, "ssh-socks5-proxy: Address type not supported: %u\n", _resp.atyp);
            return false;
        }
        return true;
    }
}
bool sl_tcpsocket::connect( const sl_ip& ip, uint32_t port, uint32_t timeout )
{
    return this->connect((uint32_t)ip, port, timeout);
}
bool sl_tcpsocket::connect( const sl_peerinfo &peer, uint32_t timeout )
{
    return this->connect((uint32_t)peer.ipaddress, peer.port_number, timeout);
}

bool sl_tcpsocket::connect( const string &ipaddr, uint32_t port, uint32_t timeout )
{
    if ( m_is_connected_to_proxy == false ) {
        return this->_internal_connect( ipaddr, port, timeout );
    } else {
        // Establish a connection through the proxy server.
        u_int8_t _buffer[256] = {0};
        // Socks info
        u_int16_t _host_port = htons((u_int16_t)port); // the port must be uint16

        /* Assemble the request packet */
		sl_socks5_connect_request _req;
		_req.atyp = sl_socks5atyp_dname;
		memcpy(_buffer, (char *)&_req, sizeof(_req));

		unsigned int _pos = sizeof(_req);
		_buffer[_pos] = (uint8_t)ipaddr.size();
		_pos += 1;
		memcpy(_buffer + _pos, ipaddr.data(), ipaddr.size());
		_pos += ipaddr.size();
		memcpy(_buffer + _pos, &_host_port, sizeof(_host_port));
		_pos += sizeof(_host_port);
		
        if (write(m_socket, _buffer, _pos) == -1) {
            return false;
        }

        /*
         * The maximum size of the protocol message we are waiting for is 10
         * bytes -- VER[1], REP[1], RSV[1], ATYP[1], BND.ADDR[4] and
         * BND.PORT[2]; see RFC 1928, section "6. Replies" for more details.
         * Everything else is already a part of the data we are supposed to
         * deliver to the requester. We know that BND.ADDR is exactly 4 bytes
         * since as you can see below, we accept only ATYP == 1 which specifies
         * that the IPv4 address is in a binary format.
         */
		sl_socks5_ipv4_response _resp;
        if (read(m_socket, (char *)&_resp, sizeof(_resp)) == -1) {
            return false;
        }

        /* Check the server's version. */
		if ( _resp.ver != 0x05 ) {
            lerror << "Unsupported SOCKS version: " << _resp.ver << lend;
            return false;
        }
        if (_resp.rep != sl_socks5rep_successed) {
            lerror << sl_socks5msg((sl_socks5rep)_resp.rep) << lend;
			return false;
		}

        /* Check ATYP */
		if ( _resp.atyp != sl_socks5atyp_ipv4 ) {
            lerror << "ssh-socks5-proxy: Address type not supported: " << _resp.atyp << lend;
            return false;
        }
        return true;
    }
}

// Listen on specified port and address, default is 0.0.0.0
bool sl_tcpsocket::listen( uint32_t port, uint32_t ipaddr )
{
    struct sockaddr_in _sock_addr;
    m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;

	// Make the socket reusable
	this->set_reusable(true);

    memset((char *)&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(port);
    _sock_addr.sin_addr.s_addr = htonl(ipaddr);

    if ( ::bind(m_socket, (struct sockaddr *)&_sock_addr, sizeof(_sock_addr)) == -1 ) {
        SL_NETWORK_CLOSESOCK( m_socket );
        return false;
    }
    if ( -1 == ::listen(m_socket, 100) ) {
        SL_NETWORK_CLOSESOCK( m_socket );
        return false;
    }
    m_is_listening = true;
    return true;
}

void sl_tcpsocket::monitor()
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return;
    if ( m_is_listening ) {
        sl_poller::server().bind_tcp_server(m_socket);
    } else {
        m_iswrapper = true;
        sl_poller::server().monitor_socket(m_socket, true);
    }
}
// Try to get the original destination
bool sl_tcpsocket::get_original_dest( string &address, uint32_t &port )
{
#if SL_TARGET_LINUX
    struct sockaddr_in _dest_addr;
    socklen_t _socklen = sizeof(_dest_addr);
    int _error = getsockopt( m_socket, SOL_IP, SO_ORIGINAL_DST, &_dest_addr, &_socklen );
    if ( _error ) return false;
    uint32_t _ipaddr = _dest_addr.sin_addr.s_addr;
    port = ntohs(_dest_addr.sin_port);
    network_int_to_ipaddress( _ipaddr, address );
    return true;
#else
    return false;
#endif
}

// Read data from the socket until timeout or get any data.
SO_READ_STATUE sl_tcpsocket::read_data( string &buffer, uint32_t timeout)
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return SO_READ_CLOSE;

	buffer.resize(0);
    struct timeval _tv = { (long)timeout / 1000, 
        static_cast<int>(((long)timeout % 1000) * 1000) };

    fd_set recvFs;
    FD_ZERO( &recvFs );
    FD_SET( m_socket, &recvFs );

    // Buffer
	SO_READ_STATUE _st = SO_READ_WAITING;

    // Wait for the incoming
    int _retCode = 0;
   	do {
    	_retCode = ::select( m_socket + 1, &recvFs, NULL, NULL, &_tv );
    } while ( _retCode < 0 && errno == EINTR );

    if ( _retCode < 0 ) // Error
        return (SO_READ_STATUE)(_st | SO_READ_CLOSE);
    if ( _retCode == 0 )// TimeOut
        return (SO_READ_STATUE)(_st | SO_READ_TIMEOUT);

	unsigned int _rmem = 0;
	socklen_t _optlen = sizeof(_rmem);
	getsockopt(m_socket, SOL_SOCKET, SO_RCVBUF, &_rmem, &_optlen);
	buffer.resize(_rmem);

    // Get data from the socket cache
    _retCode = ::recv( m_socket, &buffer[0], _rmem, 0 );
    // Error happen when read data, means the socket has become invalidate
	// Or receive EOF, which should close the socket
    if ( _retCode <= 0 ) {
		buffer.resize(0);
		return (SO_READ_STATUE)(_st | SO_READ_CLOSE);
	}
	buffer.resize(_retCode);
	_st = SO_READ_DONE;
    return _st;
}

SO_READ_STATUE sl_tcpsocket::recv( string &buffer, unsigned int max_buffer_len ) {
	if ( SOCKET_NOT_VALIDATE(m_socket) ) return SO_READ_CLOSE;
	
	// Socket must be nonblocking
	buffer.clear();
	buffer.resize(max_buffer_len);
	do {
		int _retCode = ::recv(m_socket, &buffer[0], max_buffer_len, 0 );
		if ( _retCode < 0 ) {
			int _error = 0, _len = sizeof(int);
			getsockopt( m_socket, SOL_SOCKET, SO_ERROR,
					(char *)&_error, (socklen_t *)&_len);
			if ( _error == EINTR ) continue;	// signal 7, retry
			// Other error
			buffer.resize(0);
			return SO_READ_CLOSE;
		} else if ( _retCode == 0 ) {
			// Peer Close
			buffer.resize(0);
			return SO_READ_CLOSE;
		} else {
			buffer.resize(_retCode);
			return SO_READ_DONE;
		}
	} while ( true );
	return SO_READ_DONE;
}

// Write data to peer.
bool sl_tcpsocket::write_data( const string &data )
{
    if ( data.size() == 0 ) return false;
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;

    int _lastSent = 0;

    unsigned int _length = data.size();
    const char *_data = data.c_str();

    while ( _length > 0 )
    {
        _lastSent = ::send( m_socket, _data, 
           	_length, 0 | SL_NETWORK_NOSIGNAL );
        if( _lastSent <= 0 ) {
            // Failed to send
            return false;
        }
		_data += _lastSent;
		_length -= _lastSent;
    }
    return true;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/udpsocket.cpp

sl_udpsocket::sl_udpsocket(bool iswrapper)
: sl_socket(iswrapper)
{
    // nothing
}
sl_udpsocket::sl_udpsocket(SOCKET_T so)
: sl_socket(true)
{
    m_socket = so;
}
sl_udpsocket::sl_udpsocket(SOCKET_T so, struct sockaddr_in addr)
: sl_socket(true)
{
    m_socket = so;
    // Copy the address
    memcpy(&m_sock_addr, &addr, sizeof(addr));
}

sl_udpsocket::~sl_udpsocket()
{
}

// The IP Address information for peer socket
string & sl_udpsocket::ipaddress( string & ipstr ) const
{
    network_int_to_ipaddress(m_sock_addr.sin_addr.s_addr, ipstr);
    return ipstr;
}
// The Port of peer socket
uint32_t sl_udpsocket::port() const
{
    return ntohs(m_sock_addr.sin_port);
}

// Connect to peer
bool sl_udpsocket::connect( const uint32_t inaddr, uint32_t port, uint32_t timeout )
{
    memset( &m_sock_addr, 0, sizeof(m_sock_addr) );
    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(port);
    m_sock_addr.sin_addr.s_addr = inaddr;

    // Create Socket Handle
    m_socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) {
        return false;
    }
    // Bind to 0, so we can get the port number by getsockname
    struct sockaddr_in _usin = {};
    _usin.sin_family = AF_INET;
    _usin.sin_addr.s_addr = htonl(INADDR_ANY);
    _usin.sin_port = 0;
    bind(m_socket, (struct sockaddr *)&_usin, sizeof(_usin));

    return true;
}
bool sl_udpsocket::connect( const sl_ip& ip, uint32_t port, uint32_t timeout )
{
    return this->connect((uint32_t)ip, port, timeout);
}
bool sl_udpsocket::connect( const sl_peerinfo &peer, uint32_t timeout )
{
    return this->connect((uint32_t)peer.ipaddress, peer.port_number, timeout);
}
bool sl_udpsocket::connect( const string &ipaddr, uint32_t port, uint32_t timeout )
{
    memset( &m_sock_addr, 0, sizeof(m_sock_addr) );
    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(port);
    char _ip[16];
    if ( inet_aton(network_domain_to_ip(ipaddr.c_str(), _ip, 16), &m_sock_addr.sin_addr) == 0 ) {
        return false;
    }

    // Create Socket Handle
    m_socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) {
        return false;
    }
    // Bind to 0, so we can get the port number by getsockname
    struct sockaddr_in _usin = {};
    _usin.sin_family = AF_INET;
    _usin.sin_addr.s_addr = htonl(INADDR_ANY);
    _usin.sin_port = 0;
    bind(m_socket, (struct sockaddr *)&_usin, sizeof(_usin));

    return true;
}
// Listen on specified port and address, default is 0.0.0.0
bool sl_udpsocket::listen( uint32_t port, uint32_t ipaddr )
{
    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;
    memset((char *)&m_sock_addr, 0, sizeof(m_sock_addr));

    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(port);
    m_sock_addr.sin_addr.s_addr = htonl(ipaddr);
    if ( ::bind(m_socket, (struct sockaddr *)&m_sock_addr, sizeof(m_sock_addr)) == -1 ) {
        SL_NETWORK_CLOSESOCK(m_socket);
        return false;
    }
    return true;
}

void sl_udpsocket::monitor()
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return;
    if ( m_is_listening ) {
        sl_poller::server().bind_udp_server(m_socket);
    } else {
        m_iswrapper = true;
        sl_poller::server().monitor_socket(m_socket, true);
    }
}

// Read data from the socket until timeout or get any data.
SO_READ_STATUE sl_udpsocket::read_data( string &buffer, uint32_t timeout )
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return SO_READ_CLOSE;

    // Set the receive time out
    struct timeval _tv = { (int)timeout / 1000, (int)timeout % 1000 * 1000 };
    if ( setsockopt( m_socket, SOL_SOCKET, SO_RCVTIMEO, &_tv, sizeof(_tv) ) == -1)
        return SO_READ_CLOSE;

    buffer.clear();
    size_t _bsize = buffer.size();
    buffer.resize(_bsize + 1024);

    int _data_len = 0;
    do {
        unsigned _so_len = sizeof(m_sock_addr);
        _data_len = ::recvfrom( m_socket, &buffer[_bsize], 1024, 0,
            (struct sockaddr *)&m_sock_addr, &_so_len);
        if ( _data_len == 1024 ) {
            // m_buffer is full, so maybe still has data
            _bsize = buffer.size();
            buffer.resize(_bsize + 1024);
            continue;
        } else if ( _data_len < 0 ) {
            // Error Occurred
            buffer.resize(0);
        } else {
            _bsize += _data_len;
            buffer.resize(_bsize);
        }
        break;
    } while( true );

    return (_data_len >= 0) ? SO_READ_DONE : SO_READ_TIMEOUT;
}
SO_READ_STATUE sl_udpsocket::recv(string &buffer, unsigned int max_buffer_len)
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return SO_READ_CLOSE;

    buffer.clear();
    buffer.resize(max_buffer_len);

    do {
        unsigned _so_len = sizeof(m_sock_addr);
        int _retCode = ::recvfrom( m_socket, &buffer[0], max_buffer_len, 0,
            (struct sockaddr *)&m_sock_addr, &_so_len);
        if ( _retCode < 0 ) {
            int _error = 0, _len = sizeof(int);
            getsockopt( m_socket, SOL_SOCKET, SO_ERROR,
                    (char *)&_error, (socklen_t *)&_len);
            if ( _error == EINTR ) continue;    // signal 7, retry
            // Other error
            buffer.resize(0);
            return SO_READ_CLOSE;
        } else if ( _retCode == 0 ) {
            // Peer Close
            buffer.resize(0);
            return SO_READ_CLOSE;
        } else {
            buffer.resize(_retCode);
            return SO_READ_DONE;
        }
    } while ( true );
}

// Write data to peer.
bool sl_udpsocket::write_data( const string &data )
{
    if ( data.size() == 0 ) return false;
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;

    int _allSent = 0;
    int _lastSent = 0;

    uint32_t _length = data.size();
    const char *_data = data.c_str();

    while ( (unsigned int)_allSent < _length )
    {
        _lastSent = ::sendto(m_socket, _data + _allSent, 
            (_length - (unsigned int)_allSent), 0, 
            (struct sockaddr *)&m_sock_addr, sizeof(m_sock_addr));
        if ( _lastSent < 0 ) {
            // Failed to send
            return false;
        }
        _allSent += _lastSent;
    }
    return true;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// End of amalgamate file
