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

// Current Version: 0.6-rc5-10-gf2198bc

#include "socketlite.h"
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

/*
IP Range, x.x.x.x/n
*/
void sl_iprange::parse_range_from_string(const string &format_string)
{
    // This is invalidate range
    low_ = high_ = (uint32_t)-1;

    size_t _slash_pos = format_string.find('/');
    string _ipstr, _maskstr;
    if ( _slash_pos == string::npos ) {
        _ipstr = format_string;
        _maskstr = "32";
    } else {
        _ipstr = format_string.substr(0, _slash_pos);
        _maskstr = format_string.substr(_slash_pos + 1);
    }

    sl_ip _lowip(_ipstr);
    if ( (uint32_t)_lowip == 0 ) return;  // Invalidate 

    // Mask part
    if ( _maskstr.size() > 2 ) {
        sl_ip _highip(_maskstr);
        if ( (uint32_t)_highip == 0 ) return;     // Invalidate Second Part
        if ( _highip < _lowip ) return; // Invalidate order of the range
        low_ = _lowip;
        high_ = _highip;
    } else {
        uint32_t _mask = stoi(_maskstr, nullptr, 10);
        if ( _mask > 32 ) return;
        uint32_t _fmask = 0xFFFFFFFF;
        _fmask <<= (32 - _mask);
        low_ = ntohl(_lowip) & _fmask;
        high_ = low_ | (~_fmask);
        low_ = htonl(low_);
        high_ = htonl(high_);
    }
}
sl_iprange::sl_iprange() : low_((uint32_t)-1), high_((uint32_t)-1){ }
sl_iprange::sl_iprange(const string & format_string) {
    this->parse_range_from_string(format_string);
}
sl_iprange::sl_iprange(uint32_t low, uint32_t high) : low_(low), high_(high) {
    if ( ntohl(high_) < ntohl(low_) ) {
        low_ = high_ = (uint32_t)-1;
    }
}
sl_iprange::sl_iprange(const sl_iprange &rhs) : low_(rhs.low_), high_(rhs.high_) { }
sl_iprange & sl_iprange::operator = (const sl_iprange & rhs) {
    low_ = rhs.low_;
    high_ = rhs.high_;
    return *this;
}
sl_iprange & sl_iprange::operator = (const string & format_string) {
    this->parse_range_from_string(format_string);
    return *this;
}

sl_iprange::operator const string() const {
    string _lowstr = sl_ip(low_);
    string _highstr = sl_ip(high_);
    return _lowstr + " - " + _highstr;
}
bool sl_iprange::is_ip_in_range(const sl_ip& ip) {
    uint32_t _ip = ntohl(ip);
    uint32_t _low = ntohl(low_);
    uint32_t _high = ntohl(high_);
    return _ip >= _low && _ip <= _high;
    //return ip >= sl_ip(low_) && ip <= sl_ip(high_);
}
sl_iprange::operator bool() const {
    return low_ != (uint32_t)-1 && high_ != (uint32_t)-1;
}

// Output the ip range
ostream & operator << (ostream &os, const sl_iprange &range) {
    os << range.operator const string();
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

// src/dns.cpp
#include <arpa/inet.h>

#ifdef SOCK_LITE_INTEGRATION_DNS

// Get the formated domain in the dns packet.
// The domain "www.google.com", will be "\3www\6google\3com\0".
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

// support the offset in the dns packet
int _dns_get_format_domain( const char *begin_of_domain, const char *begin_of_pkt, string &domain ) {
    domain.clear();
    int _readsize = 0;
    for ( ;; ) {
        uint8_t _l = begin_of_domain[_readsize];
        _readsize += 1;
        if ( (_l & 0xC0) == 0xC0 ) {
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
            _dns_get_format_domain(begin_of_pkt + _offset, _reset_domain);
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

sl_dns_packet::sl_dns_packet()
{
    packet_data_.append((size_t)packet_header_size, '\0');
}
sl_dns_packet::sl_dns_packet(const string& packet, bool is_tcp_packet)
{
    // Force to resize to minimal header size
    if ( packet.size() < packet_header_size ) {
        packet_data_.append((size_t)packet_header_size, '\0');
    } else {
        const char *_data = packet.c_str();
        size_t _length = packet.size();
        if ( is_tcp_packet ) {
            _data += sizeof(uint16_t);
            _length -= sizeof(uint16_t);
        }
        packet_data_.append(_data, _length);
    }
}
sl_dns_packet::sl_dns_packet(const sl_dns_packet& rhs) 
: packet_data_(rhs.packet_data_) { }

sl_dns_packet::sl_dns_packet(const sl_dns_packet&& rrhs)
: packet_data_(move(rrhs.packet_data_)) { }

sl_dns_packet::sl_dns_packet(uint16_t trans_id, const string& query_domain)
{
    packet_data_.resize(packet_header_size);
    this->set_transaction_id(trans_id);
    this->set_is_query_request(true);
    this->set_is_recursive_desired(true);
    this->set_opcode(sl_dns_opcode_standard);
    this->set_query_domain(query_domain);
}

// Transaction ID
uint16_t sl_dns_packet::get_transaction_id() const
{
    return ntohs(*(const uint16_t *)(packet_data_.c_str()));
}
void sl_dns_packet::set_transaction_id(uint16_t tid)
{
    ((uint16_t *)&(packet_data_[0]))[0] = htons(tid);
}

// Request Type
bool sl_dns_packet::get_is_query_request() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (_h_flag & 0x8000) == 0;
}
bool sl_dns_packet::get_is_response_request() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (_h_flag & 0x8000) > 0;
}
void sl_dns_packet::set_is_query_request(bool isqr)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    if ( isqr ) {
        _h_flag &= 0x7FFF;
    } else {
        _h_flag |= 0x8000;
    }
    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

// Op Code
sl_dns_opcode sl_dns_packet::get_opcode() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (sl_dns_opcode)((_h_flag >> 11) & 0x000F);
}
void sl_dns_packet::set_opcode(sl_dns_opcode opcode)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);

    // Setup the mask
    uint16_t _mask = (((opcode & 0x000F) << 11) | 0x87FF);  // 1000 0111 1111 1111
    _h_flag &= _mask;

    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

// AA
bool sl_dns_packet::get_is_authoritative() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (_h_flag & 0x0400) > 0;
}
void sl_dns_packet::set_is_authoritative(bool auth)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);

    if ( auth ) {
        _h_flag |= 0x0400;
    } else {
        _h_flag &= 0xFBFF;
    }

    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

// Truncation
bool sl_dns_packet::get_is_truncation() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (_h_flag & 0x0200) > 0;
}

void sl_dns_packet::set_is_truncation(bool trunc)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);

    if ( trunc ) {
        _h_flag |= 0x0200;
    } else {
        _h_flag &= 0xFDFF;
    }

    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

// Recursive
bool sl_dns_packet::get_is_recursive_desired() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (_h_flag & 0x0100) > 0;
}
void sl_dns_packet::set_is_recursive_desired(bool rd)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    if ( rd ) {
        _h_flag |= 0x0100;
    } else {
        _h_flag &= 0xFEFF;
    }
    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

// Recursive available
bool sl_dns_packet::get_is_recursive_available() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (_h_flag & 0x0080) > 0;
}
void sl_dns_packet::set_is_recursive_available(bool recursive)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);

    if ( recursive ) {
        _h_flag |= 0x0080;
    } else {
        _h_flag &= 0xFF7F;
    }

    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

sl_dns_rcode sl_dns_packet::get_resp_code() const
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    return (sl_dns_rcode)(_h_flag & 0x000F);
}
void sl_dns_packet::set_resp_code(sl_dns_rcode rcode)
{
    uint16_t _h_flag = ntohs(((const uint16_t *)(packet_data_.c_str()))[1]);
    _h_flag |= (rcode & 0x000F);
    ((uint16_t *)&(packet_data_[0]))[1] = htons(_h_flag);
}

uint16_t sl_dns_packet::get_qd_count() const
{
    return ntohs(((const uint16_t *)(packet_data_.c_str()))[2]);
}
uint16_t sl_dns_packet::get_an_count() const
{
    return ntohs(((const uint16_t *)(packet_data_.c_str()))[3]);
}
uint16_t sl_dns_packet::get_ns_count() const
{
    return ntohs(((const uint16_t *)(packet_data_.c_str()))[4]);
}
uint16_t sl_dns_packet::get_ar_count() const
{
    return ntohs(((const uint16_t *)(packet_data_.c_str()))[5]);
}

// Operators
sl_dns_packet& sl_dns_packet::operator = (const sl_dns_packet& rhs)
{
    packet_data_ = rhs.packet_data_;
    return *this;
}
sl_dns_packet& sl_dns_packet::operator = (const sl_dns_packet&& rrhs)
{
    packet_data_ = move(rrhs.packet_data_);
    return *this;
}

const string sl_dns_packet::get_query_domain() const
{
    string _domain;
    if ( packet_data_.size() > (packet_header_size + 2 + 2) ) {
        _dns_get_format_domain(packet_data_.c_str() + packet_header_size, _domain);
    }
    return _domain;
}
void sl_dns_packet::set_query_domain(const string& domain, sl_dns_qtype qtype, sl_dns_qclass qclass)
{
    // Format the query domain
    string _fdomain;
    _dns_format_domain(domain, _fdomain);

    // Copy the domain
    packet_data_.resize(packet_header_size + _fdomain.size() + 2 * sizeof(uint8_t) + 2 * sizeof(uint8_t));
    memcpy(&packet_data_[packet_header_size], _fdomain.c_str(), _fdomain.size());

    // Set type and class
    uint16_t *_f_area = ((uint16_t *)(&packet_data_[packet_header_size + _fdomain.size()]));
    _f_area[0] = htons(qtype);
    _f_area[1] = htons(qclass);

    // Update QD count
    ((uint16_t *)&(packet_data_[0]))[2] = htons(1);
}

// A-Records
const vector<sl_ip> sl_dns_packet::get_A_records() const
{
    string _qdomain(this->get_query_domain());
    vector<sl_ip> _result_list;

    if ( _qdomain.size() == 0 ) return _result_list;

    // Get the data offset
    // Header Size + Domain Size(+2) + QType + QClass
    const char *_pbuf = (
        packet_data_.c_str() +      // Start point
        packet_header_size +        // Header Fixed Size
        (_qdomain.size() + 2) +     // Domain Size + 2(start length, and \0)
        2 +                         // QType
        2                           // QClass
        );

    uint16_t _an = this->get_an_count();
    for ( uint16_t i = 0; i < _an; ++i ) {
        string _domain;
        int _dsize = _dns_get_format_domain(_pbuf, packet_data_.c_str(), _domain);
        _pbuf += _dsize;

        // Get the record type
        uint16_t _type = ntohs(((uint16_t *)_pbuf)[0]);
        _pbuf += sizeof(uint16_t);

        bool _is_a_records = ((sl_dns_qtype)_type == sl_dns_qtype_host);

        // Skip QClass
        _pbuf += sizeof(uint16_t);
        // Skip TTL
        _pbuf += sizeof(uint32_t);

        // Get RData Length
        uint16_t _rlen = ntohs(*(uint16_t *)_pbuf);
        _pbuf += sizeof(uint16_t);

        if ( _is_a_records ) {
            uint32_t _a_rec = *(uint32_t *)_pbuf;
            _result_list.emplace_back(sl_ip(_a_rec));
        }
        _pbuf += _rlen;
    }
    return _result_list;
}
void sl_dns_packet::set_A_records(const vector<sl_ip> & a_records)
{
    // Check if has set the query domain
    if ( packet_data_.size() <= (packet_header_size + 2 + 2) ) return;
    if ( a_records.size() == 0 ) return;

    // This packet should be a response
    this->set_is_query_request(false);

    // Set the response code, no error
    this->set_resp_code(sl_dns_rcode_noerr);

    // Update answer count
    ((uint16_t *)&(packet_data_[0]))[3] = htons(a_records.size() + this->get_an_count());

    // All length: incoming packet(header + query domain) + 2bytes domain-name(offset to query domain) + 
    // 2 bytes type(A) + 2 bytes class(IN) + 4 bytes(TTL) + 2bytes(r-length) + 4bytes(r-data, ipaddr)
    size_t _append_size = (2 + 2 + 2 + 4 + 2 + 4) * a_records.size();
    size_t _current_size = packet_data_.size();
    packet_data_.resize(_current_size + _append_size);

    // Offset
    uint16_t _name_offset = packet_header_size;
    _name_offset |= 0xC000;
    _name_offset = htons(_name_offset);

    // Generate the RR
    size_t _boffset = _current_size;
    for ( auto _ip : a_records ) {
        // Name
        uint16_t *_pname = (uint16_t *)(&packet_data_[0] + _boffset);
        *_pname = _name_offset;
        _boffset += sizeof(uint16_t);

        // Type
        uint16_t *_ptype = (uint16_t *)(&packet_data_[0] + _boffset);
        *_ptype = htons((uint16_t)sl_dns_qtype_host);
        _boffset += sizeof(uint16_t);

        // Class
        uint16_t *_pclass = (uint16_t *)(&packet_data_[0] + _boffset);
        *_pclass = htons((uint16_t)sl_dns_qclass_in);
        _boffset += sizeof(uint16_t);

        // TTL
        uint32_t *_pttl = (uint32_t *)(&packet_data_[0] + _boffset);
        *_pttl = htonl(30 * 60);    // 30 mins
        _boffset += sizeof(uint32_t);

        // RLENGTH
        uint16_t *_prlen = (uint16_t *)(&packet_data_[0] + _boffset);
        *_prlen = htons(4);
        _boffset += sizeof(uint16_t);

        // RDATA
        uint32_t *_prdata = (uint32_t *)(&packet_data_[0] + _boffset);
        *_prdata = _ip;
        _boffset += sizeof(uint32_t);
    }
}

// Dump all C-Name Records in the dns packet
const vector<string> sl_dns_packet::get_C_Names() const
{
    string _qdomain(this->get_query_domain());
    vector<string> _result_list;

    if ( _qdomain.size() == 0 ) return _result_list;

    // Get the data offset
    // Header Size + Domain Size(+2) + QType + QClass
    const char *_pbuf = (
        packet_data_.c_str() +      // Start point
        packet_header_size +        // Header Fixed Size
        (_qdomain.size() + 2) +     // Domain Size + 2(start length, and \0)
        2 +                         // QType
        2                           // QClass
        );

    uint16_t _an = this->get_an_count();
    for ( uint16_t i = 0; i < _an; ++i ) {
        string _domain;
        int _dsize = _dns_get_format_domain(_pbuf, packet_data_.c_str(), _domain);
        _pbuf += _dsize;

        // Get the record type
        uint16_t _type = ntohs(*(uint16_t *)_pbuf);
        _pbuf += sizeof(uint16_t);

        bool _is_c_name = ((sl_dns_qtype)_type == sl_dns_qtype_cname);

        // Skip QClass
        _pbuf += sizeof(uint16_t);
        // Skip TTL
        _pbuf += sizeof(uint32_t);

        // Get RData Length
        uint16_t _rlen = ntohs(*(uint16_t *)_pbuf);
        _pbuf += sizeof(uint16_t);

        if ( _is_c_name ) {
            string _cname;
            _dns_get_format_domain(_pbuf, packet_data_.c_str(), _cname);
            _result_list.emplace_back(_cname);
        }
        _pbuf += _rlen;
    }
    return _result_list;
}
// Append C-Name to the end of the dns packet
void sl_dns_packet::set_C_Names(const vector<string> & c_names)
{
    // Check if has set the query domain
    if ( packet_data_.size() <= (packet_header_size + 2 + 2) ) return;
    if ( c_names.size() == 0 ) return;

    // This packet should be a response
    this->set_is_query_request(false);

    // Set the response code, no error
    this->set_resp_code(sl_dns_rcode_noerr);

    // Update answer count
    ((uint16_t *)&(packet_data_[0]))[3] = htons(c_names.size() + this->get_an_count());

    // All length: incoming packet(header + query domain) + 2bytes domain-name(offset to query domain) + 
    // 2 bytes type(A) + 2 bytes class(IN) + 4 bytes(TTL) + 2bytes(r-length) + n-bytes data
    size_t _append_size = 0;
    for ( auto &_name : c_names ) {
        _append_size += (2 + 2 + 2 + 4 + 2 + _name.size());
    }
    size_t _current_size = packet_data_.size();
    packet_data_.resize(_current_size + _append_size);

    // Offset
    uint16_t _name_offset = packet_header_size;
    _name_offset |= 0xC000;
    _name_offset = htons(_name_offset);

    // Generate the RR
    size_t _boffset = _current_size;
    for ( auto _cname : c_names ) {
        // Name
        uint16_t *_pname = (uint16_t *)(&packet_data_[0] + _boffset);
        *_pname = _name_offset;
        _boffset += sizeof(uint16_t);

        // Type
        uint16_t *_ptype = (uint16_t *)(&packet_data_[0] + _boffset);
        *_ptype = htons((uint16_t)sl_dns_qtype_cname);
        _boffset += sizeof(uint16_t);

        // Class
        uint16_t *_pclass = (uint16_t *)(&packet_data_[0] + _boffset);
        *_pclass = htons((uint16_t)sl_dns_qclass_in);
        _boffset += sizeof(uint16_t);

        // TTL
        uint32_t *_pttl = (uint32_t *)(&packet_data_[0] + _boffset);
        *_pttl = htonl(30 * 60);    // 30 mins
        _boffset += sizeof(uint32_t);

        // RLENGTH
        uint16_t *_prlen = (uint16_t *)(&packet_data_[0] + _boffset);
        *_prlen = htons((uint16_t)_cname.size() + 2);
        _boffset += sizeof(uint16_t);

        // RDATA
        string _fcname;
        _dns_format_domain(_cname, _fcname);
        char *_prdata = (char *)(&packet_data_[0] + _boffset);
        memcpy(_prdata, _fcname.c_str(), _fcname.size());
        _boffset += _fcname.size();
    }
}

// Size
size_t sl_dns_packet::size() const { return packet_data_.size(); }
// Buffer Point
const char *const sl_dns_packet::pbuf() { return packet_data_.c_str(); }

// String Cast
sl_dns_packet::operator const string& () const { return packet_data_; }
const string& sl_dns_packet::str() const { return packet_data_; }

const string sl_dns_packet::to_tcp_packet() const
{
    // Initialize an empty packet
    string _packet(2 + packet_data_.size(), '\0');
    *((uint16_t *)&_packet[0]) = htons(packet_data_.size());
    memcpy(&_packet[2], packet_data_.c_str(), packet_data_.size());
    return _packet;
}

#endif

// cleandns.dns.cpp
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/poller.cpp

// Convert the EVENT_ID to string
const string sl_event_name(uint32_t eid)
{
	static string _accept = " SL_EVENT_ACCEPT ";
	static string _data = " SL_EVENT_DATA|SL_EVENT_READ ";
	static string _failed = " SL_EVENT_FAILED ";
	static string _write = " SL_EVENT_WRITE|SL_EVENT_CONNECT ";
	static string _timeout = " SL_EVENT_TIMEOUT ";
	static string _unknown = " Unknown Event ";

	string _name;
	if ( eid & SL_EVENT_ACCEPT ) _name += _accept;
	if ( eid & SL_EVENT_DATA ) _name += _data;
	if ( eid & SL_EVENT_FAILED ) _name += _failed;
	if ( eid & SL_EVENT_WRITE ) _name += _write;
	if ( eid & SL_EVENT_TIMEOUT ) _name += _timeout;
	if ( _name.size() == 0 ) return _unknown;
	return _name;
}
// Output of the event
ostream & operator << (ostream &os, const sl_event & e)
{
    os
        << "event " << sl_event_name(e.event) << " for "
        << (e.socktype == IPPROTO_TCP ? "tcp socket " : "udp socket ") << e.so;
    return os;
}

// Create a failed or timedout event structure object
sl_event sl_event_make_failed(SOCKET_T so) {
	sl_event _e;
	memset(&_e, 0, sizeof(_e));
	_e.so = so;
	_e.event = SL_EVENT_FAILED;
	return _e;
}
sl_event sl_event_make_timeout(SOCKET_T so) {
	sl_event _e;
	memset(&_e, 0, sizeof(_e));
	_e.so = so;
	_e.event = SL_EVENT_TIMEOUT;
	return _e;
}

sl_poller::sl_poller()
	:m_fd(-1), m_events(NULL)
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

size_t sl_poller::fetch_events( sl_poller::earray &events, unsigned int timedout ) {
	if ( m_fd == -1 ) return 0;
	int _count = 0;
#if SL_TARGET_LINUX
	do {
		_count = epoll_wait( m_fd, m_events, CO_MAX_SO_EVENTS, timedout );
	} while ( _count < 0 && errno == EINTR );
#elif SL_TARGET_MAC
	struct timespec _ts = { timedout / 1000, timedout % 1000 * 1000 * 1000 };
	_count = kevent(m_fd, NULL, 0, m_events, CO_MAX_SO_EVENTS, &_ts);
#endif

	time_t _now_time = time(NULL);

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

			// Remove the timeout info
			lock_guard<mutex> _(m_timeout_mutex);
			m_timeout_map.erase(_e.so);

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
		else {
			// R/W
#if SL_TARGET_LINUX
			_e.so = _pe->data.fd;
#elif SL_TARGET_MAC
			_e.so = _pe->ident;
#endif
			int _error = 0, _len = sizeof(int);
			// Get the type
            int _type;
			getsockopt( _e.so, SOL_SOCKET, SO_TYPE,
					(char *)&_type, (socklen_t *)&_len);
            if ( _type == SOCK_STREAM ) {
                _e.socktype = IPPROTO_TCP;
            } else {
                _e.socktype = IPPROTO_UDP;
            }

			// ldebug << "get event for socket: " << _e.so << lend;
			getsockopt( _e.so, SOL_SOCKET, SO_ERROR, 
					(char *)&_error, (socklen_t *)&_len);
			if ( _error == 0 ) {
				// Check if is read or write
#if SL_TARGET_LINUX
				if ( _pe->events & EPOLLIN ) {
					_e.event = SL_EVENT_DATA;
					// ldebug << "did get r/w event for socket: " << _e.so << ", event: " << sl_event_name(_e.event) << lend;
					if ( _e.socktype == IPPROTO_UDP ) {
						// Try to fetch the address info
						socklen_t _l = sizeof(_e.address);
						::recvfrom( _e.so, NULL, 0, MSG_PEEK,
			            	(struct sockaddr *)&_e.address, &_l);
					}
					events.push_back(_e);
				}
				if ( _pe->events & EPOLLOUT ) {
					_e.event = SL_EVENT_WRITE;
					// ldebug << "did get r/w event for socket: " << _e.so << ", event: " << sl_event_name(_e.event) << lend;
					events.push_back(_e);
				}
#elif SL_TARGET_MAC
				if ( _pe->filter == EVFILT_READ ) {
					_e.event = SL_EVENT_DATA;
					if ( _e.socktype == IPPROTO_UDP ) {
						// Try to fetch the address info
						socklen_t _l = sizeof(_e.address);
						::recvfrom( _e.so, NULL, 0, MSG_PEEK,
			            	(struct sockaddr *)&_e.address, &_l);
					}
				}
				else {
					_e.event = SL_EVENT_WRITE;
				}
				events.push_back(_e);
				// ldebug << "did get r/w event for socket: " << _e.so << ", event: " << sl_event_name(_e.event) << lend;
#endif
			} else {
				_e.event = SL_EVENT_FAILED;
				events.push_back(_e);
				// ldebug << "did get r/w event for socket: " << _e.so << ", event: " << sl_event_name(_e.event) << lend;
			}

			lock_guard<mutex> _(m_timeout_mutex);
			m_timeout_map.erase(_e.so);
		}
	}

	vector<SOCKET_T> _timeout_list;
	lock_guard<mutex> _(m_timeout_mutex);
	for ( auto _tit = begin(m_timeout_map); _tit != end(m_timeout_map); ++_tit ) {
		if ( _tit->second > 0 && _tit->second < _now_time ) {
			_timeout_list.push_back(_tit->first);
			#if DEBUG
			ldebug << "socket " << _tit->first << " runs time out in poller" << lend;
			#endif
		}
	}

	for ( auto _so : _timeout_list ) {
		sl_event _e;
		_e.so = _so;
		_e.event = SL_EVENT_TIMEOUT;
		events.push_back(_e);
		m_timeout_map.erase(_so);
	}

	return events.size();
}

bool sl_poller::monitor_socket( 
	SOCKET_T so, 
	bool oneshot, 
	uint32_t eid, 
	uint32_t timedout
) {
	if ( m_fd == -1 ) return false;

	// ldebug << "is going to monitor socket " << so << " for event " << sl_event_name(eid) << lend;
#if SL_TARGET_LINUX

	// Socket must be nonblocking
	unsigned long _u = 1;
	SL_NETWORK_IOCTL_CALL(so, FIONBIO, &_u);

	struct epoll_event _ee;
	_ee.data.fd = so;
	_ee.events = EPOLLET;
	if ( eid & SL_EVENT_DATA ) _ee.events |= EPOLLIN;
	if ( eid & SL_EVENT_WRITE ) _ee.events |= EPOLLOUT;

	// In default the operation should be ADD, and we
	// will try to use ADD and MOD both.
	int _op = EPOLL_CTL_ADD;
	if ( oneshot ) {
		_ee.events |= EPOLLONESHOT;
	}
	if ( -1 == epoll_ctl( m_fd, _op, so, &_ee ) ) {
		if ( errno == EEXIST ) {
			if ( -1 == epoll_ctl( m_fd, EPOLL_CTL_MOD, so, &_ee ) ) {
				lerror << "failed to monitor the socket " << so << ": " << ::strerror(errno) << lend;
				return false;
			}
		} else if ( errno == ENOENT ) {
			if ( -1 == epoll_ctl(m_fd, EPOLL_CTL_ADD, so, &_ee ) ) {
				lerror << "failed to monitor the socket " << so << ": " << ::strerror(errno) << lend;
				return false;
			}
		} else {
			lerror << "failed to monitor the socket " << so << ": " << ::strerror(errno) << lend;
			return false;
		}
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

	lock_guard<mutex> _(m_timeout_mutex);
	if ( timedout == 0 ) {
		#if DEBUG
		ldebug << "socket " << so << " will monitor infinitvie" << lend;
		#endif
		m_timeout_map[so] = 0;
	} else {
		#if DEBUG
		ldebug 
			<< "socket " << so << " monitor on event " << sl_event_name(eid) 
			<< ", will time out after " << timedout << " seconds" 
		<< lend;
		#endif
		m_timeout_map[so] = (time(NULL) + timedout);
	}
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

sl_handler_set sl_events::empty_handler() {
    sl_handler_set _s;
    memset((void *)&_s, 0, sizeof(sl_handler_set));
    return _s;
}
// sl_events member functions
sl_events::sl_events()
: timepiece_(10), rl_callback_(NULL)
{
    lock_guard<mutex> _(running_lock_);
    this->_internal_start_runloop();
}

sl_events::~sl_events()
{
    // Delete the main runloop thread
    if ( runloop_thread_->joinable() ) {
        runloop_thread_->join();
    }
    delete runloop_thread_;
    runloop_thread_ = NULL;

    // Delete the worker thread manager
    if ( thread_pool_manager_->joinable() ) {
        thread_pool_manager_->join();
    }
    delete thread_pool_manager_;
    thread_pool_manager_ = NULL;

    // Remove all worker thread
    // Close all worker in thread pool
    while ( thread_pool_.size() > 0 ) {
        this->_internal_remove_worker();
    }
}

sl_events& sl_events::server()
{
    static sl_events _ge;
    return _ge;
}

void sl_events::_internal_start_runloop()
{
    // If already running, just return
    runloop_thread_ = new thread([this]{
        _internal_runloop();
    });

    // ldebug << "in internal start runloop method, will add a new worker" << lend;
    // Add a worker
    this->_internal_add_worker();

    // Start the worker manager thread
    thread_pool_manager_ = new thread([this]{
        thread_agent _ta;

        while ( this_thread_is_running() ) {
            usleep(10000);
            bool _has_broken = false;
            do {
                _has_broken = false;
                size_t _broken_thread_index = -1;
                for ( size_t i = 0; i < thread_pool_.size(); ++i ) {
                    if ( thread_pool_[i]->joinable() ) continue;
                    _broken_thread_index = i;
                    _has_broken = true;
                    break;
                }
                if ( _has_broken ) {
                    delete thread_pool_[_broken_thread_index];
                }
            } while( _has_broken );

            if ( events_pool_.size() > (thread_pool_.size() * 10) ) {
                // ldebug << "event pending count: " << events_pool_.size() << ", worker thread pool size: " << thread_pool_.size() << lend;
                this->_internal_add_worker();
            } else if ( events_pool_.size() < (thread_pool_.size() * 2) && thread_pool_.size() > 1 ) {
                this->_internal_remove_worker();
            }
        }
    });  
}

void sl_events::_internal_runloop()
{
    thread_agent _ta;

    //ldebug << "internal runloop started" << lend;
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

        // Combine all pending events
        do {
            lock_guard<mutex> _(event_mutex_);
            for ( auto _eit = begin(event_unfetching_map_); _eit != end(event_unfetching_map_); ++_eit ) {
                if ( _eit->second.flags.eventid == 0 ) continue;    // the socket is still alve, but not active.
                auto _epit = event_unprocessed_map_.find(_eit->first);
                if ( _epit == end(event_unprocessed_map_) ) continue;
                #if DEBUG
                ldebug << "re-monitor on socket " << _eit->first << " for event " << sl_event_name(_eit->second.flags.eventid) << lend;
                #endif
                sl_poller::server().monitor_socket(_eit->first, true, _eit->second.flags.eventid, _eit->second.flags.timeout);
            }
        } while ( false );
        //ldebug << "current pending events: " << _event_list.size() << lend;
        size_t _ecount = sl_poller::server().fetch_events(_event_list, _tp);
        if ( _ecount != 0 ) {
            //ldebug << "fetch some events, will process them" << lend;
            events_pool_.notify_lots(_event_list, &event_mutex_, [&](const sl_event && e){
                if ( e.event != SL_EVENT_WRITE && e.event != SL_EVENT_DATA ) return;
                auto _eit = event_unfetching_map_.find(e.so);
                if ( _eit == end(event_unfetching_map_) ) return;
                _eit->second.flags.eventid &= (~e.event);

                // Add this event to un_processing map
                auto _epit = event_unprocessed_map_.find(e.so);
                if ( _epit == end(event_unprocessed_map_) ) {
                    event_unprocessed_map_[e.so] = {{0, e.event}};
                } else {
                    _epit->second.flags.eventid |= e.event;
                }
            });
        }
        // Invoke the callback
        if ( _fp != NULL ) {
            _fp();
        }
    }

    linfo << "internal runloop will terminated" << lend;
}

void sl_events::_internal_add_worker()
{
    thread *_worker = new thread([this](){
        thread_agent _ta;
        try {
            _internal_worker();
        } catch (exception e) {
            lcritical << "got exception in side the internal worker " << this_thread::get_id() << lend;
        }
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

    sl_event _local_event;
    sl_socket_event_handler _handler;
    while ( this_thread_is_running() ) {
        if ( !events_pool_.wait_for(milliseconds(10), [&](sl_event&& e){
            #if DEBUG
            ldebug << "processing " << e << lend;
            #endif
            _local_event = e;
            SOCKET_T _s = ((_local_event.event == SL_EVENT_ACCEPT) && 
                            (_local_event.socktype == IPPROTO_TCP)) ? 
                            _local_event.source : _local_event.so;

            lock_guard<mutex> _(event_mutex_);

            if ( e.event != SL_EVENT_WRITE && e.event != SL_EVENT_DATA ) {
                _handler = this->_fetch_handler(_s, e.event);
            } else {
                _handler = this->_replace_handler(_s, e.event, NULL);

                auto _eit = event_unprocessed_map_.find(e.so);
                if ( _eit == end(event_unprocessed_map_) ) return;
                _eit->second.flags.eventid &= (~e.event);
                if ( _eit->second.flags.eventid == 0 ) {
                    event_unprocessed_map_.erase(_eit);
                }
            }
        }) ) continue;

        if ( _handler ) {
            _handler(_local_event);
        } else {
            lwarning << "no handler for " << _local_event << lend;
        }
    }

    linfo << "the worker " << this_thread::get_id() << " will exit" << lend;
}

sl_socket_event_handler sl_events::_replace_handler(SOCKET_T so, uint32_t eid, sl_socket_event_handler h)
{
    sl_socket_event_handler _h = NULL;
    auto _hit = handler_map_.find(so);
    if ( _hit == end(handler_map_) ) return _h;
    _h = (&_hit->second.on_accept)[SL_MACRO_LAST_1_INDEX(eid)];
    if ( eid & SL_EVENT_ACCEPT ) {
        _hit->second.on_accept = h;
    }
    if ( eid & SL_EVENT_DATA ) {
        _hit->second.on_data = h;
    }
    if ( eid & SL_EVENT_FAILED ) {
        _hit->second.on_failed = h;
    }
    if ( eid & SL_EVENT_WRITE ) {
        _hit->second.on_write = h;
    }
    if ( eid & SL_EVENT_TIMEOUT ) {
        _hit->second.on_timedout = h;
    }
    return _h;
}
sl_socket_event_handler sl_events::_fetch_handler(SOCKET_T so, SL_EVENT_ID eid)
{
    sl_socket_event_handler _h = NULL;
    auto _hit = handler_map_.find(so);
    if ( _hit == end(handler_map_) ) return _h;
    _h = (&_hit->second.on_accept)[SL_MACRO_LAST_1_INDEX(eid)];
    return _h;
}

bool sl_events::_has_handler(SOCKET_T so, SL_EVENT_ID eid)
{
    bool _has = false;
    auto _epit = event_unprocessed_map_.find(so);
    if ( _epit != end(event_unprocessed_map_) ) {
        _has = ((_epit->second.flags.eventid & eid) == eid);
    }
    if ( _has ) return true;

    auto _efit = event_unfetching_map_.find(so);
    if ( _efit != end(event_unfetching_map_) ) {
        _has = ((_efit->second.flags.eventid & eid) == eid);
    }
    return _has;
}

void sl_events::bind( SOCKET_T so, sl_handler_set&& hset )
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    lock_guard<mutex> _(handler_mutex_);
    handler_map_.emplace(so, move(hset));
}
void sl_events::unbind( SOCKET_T so )
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    lock_guard<mutex> _hl(handler_mutex_);
    lock_guard<mutex> _el(event_mutex_);
    handler_map_.erase(so);
    event_unfetching_map_.erase(so);
    event_unprocessed_map_.erase(so);
}
void sl_events::update_handler( SOCKET_T so, uint32_t eid, sl_socket_event_handler&& h)
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;
    if ( eid == 0 ) return;
    if ( eid & 0xFFFFFFE0 ) return; // Invalidate event flag
    lock_guard<mutex> _(handler_mutex_);
    auto _hit = handler_map_.find(so);
    if ( _hit == end(handler_map_) ) return;
    if ( eid & SL_EVENT_ACCEPT ) {
        _hit->second.on_accept = h;
    }
    if ( eid & SL_EVENT_DATA ) {
        _hit->second.on_data = h;
    }
    if ( eid & SL_EVENT_FAILED ) {
        _hit->second.on_failed = h;
    }
    if ( eid & SL_EVENT_WRITE ) {
        _hit->second.on_write = h;
    }
    if ( eid & SL_EVENT_TIMEOUT ) {
        _hit->second.on_timedout = h;
    }
}
void sl_events::append_handler( SOCKET_T so, uint32_t eid, sl_socket_event_handler h)
{
    lock_guard<mutex> _(handler_mutex_);
    sl_socket_event_handler _oldh = this->_fetch_handler(so, (SL_EVENT_ID)eid);
    auto _newh = [_oldh, h](sl_event e) {
        if ( _oldh ) _oldh(e);
        if ( h ) h(e);
    };
    this->_replace_handler(so, eid, _newh);
}
bool sl_events::has_handler(SOCKET_T so, SL_EVENT_ID eid)
{
    if ( SOCKET_NOT_VALIDATE(so) ) return false;
    if ( eid == 0 ) return false;
    if ( eid & 0xFFFFFFE0 ) return false;

    lock_guard<mutex> _(event_mutex_);
    return this->_has_handler(so, eid);
}

void sl_events::monitor(SOCKET_T so, SL_EVENT_ID eid, sl_socket_event_handler handler, uint32_t timedout)
{
    lock_guard<mutex> _(event_mutex_);

    bool _has_event = _has_handler(so, eid);
    if ( _has_event ) {
        #if DEBUG
        ldebug 
            << "socket " << so << " has already pending the handler for event " 
            << sl_event_name(eid) << ", ignore this monitoring request" 
        << lend;
        #endif
        return;
    }

    // Add the mask
    auto _efit = event_unfetching_map_.find(so);
    if ( _efit == end(event_unfetching_map_) ) {
        event_unfetching_map_[so] = {{timedout, eid}};
    } else {
        //_efit->second.flags.timeout = timedout;
        if ( _efit->second.flags.timeout != 0 ) {
            if ( timedout == 0 ) {
                _efit->second.flags.timeout = 0;
            } else {
                _efit->second.flags.timeout = max(_efit->second.flags.timeout, timedout);
            }
        }
        _efit->second.flags.eventid |= eid;
    }

    // Update the handler
    this->update_handler(so, eid, move(handler));

    // Update the monitor status
    if ( !sl_poller::server().monitor_socket(so, true, eid, timedout) ) {
        #if DEBUG
        ldebug 
            << "failed to monitor the socket " << so << " for event " 
            << sl_event_name(eid) << ", add a FAILED event" 
        << lend;
        #endif
        events_pool_.notify_one(move(sl_event_make_failed(so)));
    }
}

void sl_events::setup(uint32_t timepiece, sl_runloop_callback cb)
{
    lock_guard<mutex> _(running_lock_);
    timepiece_ = timepiece;
    rl_callback_ = cb;
}

void sl_events::add_event(sl_event && e)
{
    //lock_guard<mutex> _(events_lock_);
    lock_guard<mutex> _(event_mutex_);
    
    auto _efit = event_unfetching_map_.find(e.so);
    if ( _efit == end(event_unfetching_map_) ) {
        event_unfetching_map_[e.so] = {{30000, e.event}};
    } else {
        _efit->second.flags.eventid = e.event;
    }
    events_pool_.notify_one(move(e));
}
void sl_events::add_tcpevent(SOCKET_T so, SL_EVENT_ID eid)
{
    //lock_guard<mutex> _(events_lock_);
    sl_event _e;
    _e.so = so;
    _e.source = INVALIDATE_SOCKET;
    _e.event = eid;
    _e.socktype = IPPROTO_TCP;

    this->add_event(move(_e));
}
void sl_events::add_udpevent(SOCKET_T so, struct sockaddr_in addr, SL_EVENT_ID eid)
{
    //lock_guard<mutex> _(events_lock_);
    sl_event _e;
    _e.so = so;
    _e.source = INVALIDATE_SOCKET;
    _e.event = eid;
    _e.socktype = IPPROTO_UDP;
    memcpy(&_e.address, &addr, sizeof(addr));

    this->add_event(move(_e));
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

sl_methods sl_socks5_handshake_handler(const string &req_pkt, string &resp_pkt) {
	sl_socks5_handshake_request *_req = (sl_socks5_handshake_request *)req_pkt.data();
	sl_socks5_handshake_response _resp(sl_method_nomethod);

	const char *_methods = req_pkt.data() + sizeof(sl_socks5_handshake_request);
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
	resp_pkt.swap(_respdata);
	return (sl_methods)_resp.method;
}

bool sl_socks5_auth_by_username(const string &req_pkt, string &resp_pkt, sl_auth_method auth) {
	if ( req_pkt.data()[0] != 1 ) return false;		// version error

	const char *_b = req_pkt.data() + 1;
	uint32_t _l = req_pkt.size() - 1;
	string _username = sl_socks5_get_string(_b, _l);
	if ( _username.size() == 0 ) return false;
	_b += (_username.size() + sizeof(uint8_t));
	_l -= (_username.size() + sizeof(uint8_t));
	string _password = sl_socks5_get_string(_b, _l);
	if ( _password.size() == 0 ) return false;

	uint8_t _result = (auth(_username, _password) ? 0 : 1);
	char _resp[2] = {1, (char)_result};
	string _respdata(_resp, 2);
	resp_pkt.swap(_respdata);
	return _result == 0;
}

bool sl_socks5_get_connect_info(const string &req_pkt, string &addr, uint16_t& port) {
	sl_socks5_connect_request *_req = (sl_socks5_connect_request *)req_pkt.data();
	sl_socks5_ipv4_response _resp(0, 0);

	for ( int _dummy = 0; _dummy == 0; _dummy++ ) {
		if ( _req->cmd != sl_socks5cmd_connect ) {
			_resp.rep = sl_socks5rep_notsupport;
			break;
		}
		const char *_data = req_pkt.data() + sizeof(sl_socks5_connect_request);
		if ( _req->atyp == sl_socks5atyp_ipv4 ) {
			uint32_t _ip = *(uint32_t *)_data;
			network_int_to_ipaddress(_ip, addr);
			port = *(uint16_t *)(_data + sizeof(uint32_t));
			break;
		}
		if ( _req->atyp == sl_socks5atyp_dname ) {
			uint32_t _l = req_pkt.size() - sizeof(sl_socks5_connect_request);
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

void sl_socks5_generate_failed_connect_to_peer(sl_socks5rep rep, string &resp_pkt) {
	sl_socks5_ipv4_response _resp(0, 0);
	_resp.rep = rep;
	string _respstring((char *)&_resp, sizeof(_resp));
	resp_pkt.swap(_respstring);
}
void sl_socks5_generate_did_connect_to_peer(const sl_peerinfo &peer, string &resp_pkt) {
	sl_socks5_ipv4_response _resp(peer.ipaddress, htons(peer.port_number));
	string _respstring((char *)&_resp, sizeof(_resp));
	resp_pkt.swap(_respstring);
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
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>


#include <queue>

// The socket's write package structure
typedef struct sl_write_packet {
    string                          packet;
    size_t                          sent_size;
    sl_peerinfo                     peerinfo;
    sl_socket_event_handler         callback;
} sl_write_packet;
typedef shared_ptr<sl_write_packet>                 sl_shared_write_packet_t;

typedef struct sl_write_info {
    shared_ptr< mutex >                             locker;
    shared_ptr< queue<sl_shared_write_packet_t> >   packet_queue;
} sl_write_info;

typedef map< SOCKET_T, sl_write_info >              sl_write_map_t;

mutex               _g_so_write_mutex;
sl_write_map_t      _g_so_write_map;

/*!
    Close the socket and release the handler set 

    @Description
    This method will close the socket(udp or tcp) and release all cache/buffer
    associalate with it.
*/
void sl_socket_close(SOCKET_T so)
{
    if ( SOCKET_NOT_VALIDATE(so) ) return;

    // ldebug << "the socket " << so << " will be unbind and closed" << lend;
    sl_events::server().unbind(so);

    // Remove all pending write package
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        _g_so_write_map.erase(so);
    } while(false);

    close(so);
}

/*
    Monitor the socket for incoming data.

    @Description
    As reading action will block current thread if there is no data right now,
    this method will add an EPOLLIN(Linux)/EVFILT_READ(BSD) event to the queue.

    In Linux, as epoll will combine read and write flag in one set, this method
    will always monitor both EPOLLIN and EPOLLOUT.
    For a BSD based system use kqueue, will only add a EVFILT_READ to the queue.
*/
void sl_socket_monitor(
    SOCKET_T tso,
    uint32_t timedout,
    sl_socket_event_handler callback
)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return;
    if ( !callback ) return;
    sl_events::server().monitor(tso, SL_EVENT_READ, callback, timedout);
}

/*
    Bind Default Failed Handler for a Socket

    @Description
    Bind the default handler for SL_EVENT_FAILED of a socket.
    In any case if the socket receive a SL_EVENT_FAILED event, will
    invoke this handler.
    Wether set this handler or not, system will close the socket
    automatically. Which means, if you receive a SL_EVENT_FAILED
    event, the socket assigned in the sl_event structure has
    already been closed.
*/
void sl_socket_bind_event_failed(SOCKET_T so, sl_socket_event_handler handler)
{
    sl_events::server().update_handler(
        so, 
        SL_EVENT_FAILED, 
        [=](sl_event e){
            sl_socket_close(e.so);
            if ( handler ) handler(e);
        }
    );
}

/*
    Bind Default TimedOut Handler for a Socket

    @Description
    Bind the default timedout handler for SL_EVENT_TIMEOUT of a socket.
    If a socket receive a timedout event, the system will invoke this
    handler.
    If not bind this handler, system will close the socket automatically,
    otherwise, a timedout socket will NOT be closed.
*/
void sl_socket_bind_event_timeout(SOCKET_T so, sl_socket_event_handler handler)
{
    sl_events::server().update_handler(
        so, 
        SL_EVENT_TIMEOUT, 
        [=](sl_event e){
            if ( handler ) handler(e);
            else sl_socket_close(e.so);
        }
    );
}

// TCP Methods
/*!
    Initialize a TCP socket.

    @Description
    This method will create a new tcp socket file descriptor, the fd will
    be set as TCP_NODELAY, SO_REUSEADDR and NON_BLOCKING.
    And will automatically bind empty handler set in the event system.
*/
SOCKET_T _raw_internal_tcp_socket_init(
    sl_socket_event_handler failed = NULL, 
    sl_socket_event_handler timedout = NULL,
    SOCKET_T tso = INVALIDATE_SOCKET
)
{
    SOCKET_T _so = tso;
    if ( SOCKET_NOT_VALIDATE(_so) ) {
        _so = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    if ( SOCKET_NOT_VALIDATE(_so) ) {
        lerror 
            << "failed to init a tcp socket: " 
            << ::strerror( errno ) 
        << lend;
        return _so;
    }
    // Set With TCP_NODELAY
    int flag = 1;
    if( setsockopt( _so, IPPROTO_TCP, 
        TCP_NODELAY, (const char *)&flag, sizeof(int) ) == -1 )
    {
        lerror 
            << "failed to set the tcp socket(" 
            << _so << ") to be TCP_NODELAY: " 
            << ::strerror( errno ) 
        << lend;
        SL_NETWORK_CLOSESOCK( _so );
        return INVALIDATE_SOCKET;
    }

    int _reused = 1;
    if ( setsockopt( _so, SOL_SOCKET, SO_REUSEADDR,
        (const char *)&_reused, sizeof(int) ) == -1)
    {
        lerror 
            << "failed to set the tcp socket(" 
            << _so << ") to be SO_REUSEADDR: " 
            << ::strerror( errno ) 
        << lend;
        SL_NETWORK_CLOSESOCK( _so );
        return INVALIDATE_SOCKET;
    }

    unsigned long _u = 1;
    if ( SL_NETWORK_IOCTL_CALL(_so, FIONBIO, &_u) < 0 ) 
    {
        lerror 
            << "failed to set the tcp socket("
            << _so << ") to be Non Blocking: " 
            << ::strerror( errno ) 
        << lend;
        SL_NETWORK_CLOSESOCK( _so );
        return INVALIDATE_SOCKET;
    }

    // Bind the default handler set.
    sl_handler_set _hset = sl_events::empty_handler();
    _hset.on_failed = [=](sl_event e) {
        sl_socket_close(e.so);
        if ( failed ) failed(e);
    };
    _hset.on_timedout = [=](sl_event e) {
        if ( timedout ) timedout(e);
        else sl_socket_close(e.so);
    };
    sl_events::server().bind(_so, move(_hset));

    // Add A Write Buffer
    sl_write_info _wi = { 
        make_shared<mutex>(), 
        make_shared< queue<sl_shared_write_packet_t> >() 
    };
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        _g_so_write_map[_so] = _wi;
    } while(false);
    return _so;
}

// Internal async connect to the peer
void _raw_internal_tcp_socket_connect(
    const sl_peerinfo& peer,
    uint32_t timedout,
    sl_socket_event_handler callback
)
{
    auto _cb = [=](sl_event e) {
        // By default, close the timed out socket when connecting failed.
        if ( e.event == SL_EVENT_TIMEOUT ) {
            sl_socket_close(e.so);
        }
        if ( callback ) callback(e);
    };
    SOCKET_T _tso = _raw_internal_tcp_socket_init(_cb, _cb);
    if ( SOCKET_NOT_VALIDATE(_tso) ) {
        sl_event _e;
        _e.so = _tso;
        _e.event = SL_EVENT_FAILED;
        callback(_e);
        return;
    }

    struct sockaddr_in _sock_addr;
    memset(&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_addr.s_addr = peer.ipaddress;
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(peer.port_number);

    if ( ::connect( 
        _tso, 
        (struct sockaddr *)&_sock_addr, 
        sizeof(_sock_addr)) == -1 ) 
    {
        int _error = 0, _len = sizeof(_error);
        getsockopt( 
            _tso, SOL_SOCKET, 
            SO_ERROR, (char *)&_error, 
            (socklen_t *)&_len);
        if ( _error != 0 ) {
            lerror 
                << "failed to connect to " 
                << peer << " on tcp socket: "
                << _tso << ", " << ::strerror( _error ) 
            << lend;
            sl_events::server().add_tcpevent(_tso, SL_EVENT_FAILED);
        } else {
            // Monitor the socket, the poller will invoke on_connect 
            // when the socket is connected or failed.
            //ldebug << "monitor tcp socket " << tso << 
            //  " for connecting" << lend;
            sl_events::server().monitor(
                _tso, SL_EVENT_CONNECT, 
                callback, timedout);
        }
    } else {
        // Add to next run loop to process the connect event.
        linfo 
            << "connect to " << peer 
            << " is too fast, the connect method return success directly" 
        << lend;
        sl_events::server().add_tcpevent(_tso, SL_EVENT_CONNECT);
    }
}

// Internal Connecton Method, Try to connect to peer with an IP list.
void _raw_internal_tcp_socket_try_connect(
    const vector<sl_peerinfo>& peer_list, 
    uint32_t index,
    uint32_t timedout,
    sl_socket_event_handler callback
)
{
    if ( peer_list.size() <= index ) {
        if ( !callback ) return;

        sl_event _e;
        _e.event = SL_EVENT_FAILED;
        if ( callback ) callback(_e);

        return;
    }
    _raw_internal_tcp_socket_connect(
        peer_list[index],
        timedout,
        [=](sl_event e) {
            if ( e.event == SL_EVENT_CONNECT ) {
                if ( callback ) callback(e);
                return;
            }
            // Try to invoke the next ip in the list.
            _raw_internal_tcp_socket_try_connect(
                peer_list, index + 1, 
                timedout, callback);
        }
    );
}

/*
    Async connect to the host via a socks5 proxy

    @Description
    Connect to host:port via a socks5 proxy.
    If the socks5 proxy is not set(like sl_peerinfo::nan()), will try to
    connect to the host in directly connection.
    If the host is not an sl_ip, then will invoke <sl_async_gethostname>
    to resolve the host first.

    If the host is connected syncized, this method will add a SL_EVENT_CONNECT
    to the events runloop and the caller will be noticed at the next
    timepiece.

    The default timeout time is 30 seconds(30000ms).
*/
void sl_tcp_socket_connect(
    const sl_peerinfo& socks5, 
    const string& host, 
    uint16_t port,
    uint32_t timedout,
    sl_socket_event_handler callback
)
{
    shared_ptr<sl_peerinfo> _psocks5 = make_shared<sl_peerinfo>(socks5);
    if ( socks5 ) {
        //ldebug << "try to connect to " << host << ":" << port << " via socks proxy " << socks5 << lend;
        _raw_internal_tcp_socket_connect(socks5, timedout, [=](sl_event e) {
            if ( e.event != SL_EVENT_CONNECT ) {
                lerror << "the socks5 proxy " << *_psocks5 << " cannot be connected" << lend;
                if ( callback ) callback(e); 
                return;
            }

            //ldebug << "did build a connection to the socks proxy on socket " << e.so << lend;

            sl_socket_bind_event_failed(e.so, [=](sl_event e) {
                lerror << "failed to connect to socks5 proxy" << lend;
                if ( callback ) callback(e);
            });
            sl_socket_bind_event_timeout(e.so, [=](sl_event e) {
                lerror << "connect to socks5 proxy timedout" << lend;
                sl_socket_close(e.so);
                if ( callback ) callback(e);
            });

            sl_socks5_noauth_request _req;
            // Exchange version info
            if (write(e.so, (char *)&_req, sizeof(_req)) < 0) {
                sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                return;
            }
            //ldebug << "did send version checking to proxy" << lend;
            sl_socket_monitor(e.so, timedout, [=](sl_event e){
                //ldebug << "proxy response for the version checking" << lend;

                string _pkt;
                if ( !sl_tcp_socket_read(e.so, _pkt) ) {
                    sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                    return;
                }
                const sl_socks5_handshake_response* _resp = (const sl_socks5_handshake_response *)_pkt.c_str();
                // This api is for no-auth proxy
                if ( _resp->ver != 0x05 && _resp->method != sl_method_noauth ) {
                    lerror << "unsupported authentication method" << lend;
                    sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                    return;
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
                    sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                    return;
                }

                //ldebug << "did send connection request to the proxy" << lend;
                // Wait for the socks5 server's response
                sl_socket_monitor(e.so, timedout, [=](sl_event e) {
                    /*
                     * The maximum size of the protocol message we are waiting for is 10
                     * bytes -- VER[1], REP[1], RSV[1], ATYP[1], BND.ADDR[4] and
                     * BND.PORT[2]; see RFC 1928, section "6. Replies" for more details.
                     * Everything else is already a part of the data we are supposed to
                     * deliver to the requester. We know that BND.ADDR is exactly 4 bytes
                     * since as you can see below, we accept only ATYP == 1 which specifies
                     * that the IPv4 address is in a binary format.
                     */
                    string _pkt;
                    if (!sl_tcp_socket_read(e.so, _pkt)) {
                        sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                        return;
                    }
                    const sl_socks5_ipv4_response* _resp = (const sl_socks5_ipv4_response *)_pkt.c_str();

                    /* Check the server's version. */
                    if ( _resp->ver != 0x05 ) {
                        lerror << "Unsupported SOCKS version: " << _resp->ver << lend;
                        sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                        return;
                    }
                    if (_resp->rep != sl_socks5rep_successed) {
                        lerror << sl_socks5msg((sl_socks5rep)_resp->rep) << lend;
                        sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                        return;
                    }

                    /* Check ATYP */
                    if ( _resp->atyp != sl_socks5atyp_ipv4 ) {
                        lerror << "ssh-socks5-proxy: Address type not supported: " << _resp->atyp << lend;
                        sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                        return;
                    }
                    //ldebug << "now we build the connection to the peer server via current proxy" << lend;
                    e.event = SL_EVENT_CONNECT;
                    if ( callback ) callback(e);
                });
            });
        });
    } else {
        //ldebug << "the socks5 is empty, try to connect to host(" << host << ") directly" << lend;
        sl_ip _host_ip(host);
        if ( (uint32_t)_host_ip == (uint32_t)-1 ) {
            //ldebug << "the host(" << host << ") is not an IP address, try to resolve first" << lend;
            // This is a domain
            sl_async_gethostname(host, [=](const vector<sl_ip> &iplist){
                if ( iplist.size() == 0 || ((uint32_t)iplist[0] == (uint32_t)-1) ) {
                    // Error
                    lerror << "failed to resolv " << host << lend;
                    sl_event _e;
                    _e.event = SL_EVENT_FAILED;
                    callback(_e);
                } else {
                    //ldebug << "resolvd the host " << host << ", trying to connect via tcp socket" << lend;
                    vector<sl_peerinfo> _peerlist;
                    for ( auto & _ip : iplist ) {
                        _peerlist.push_back(sl_peerinfo((const string &)_ip, port));
                    }
                    _raw_internal_tcp_socket_try_connect(_peerlist, 0, timedout, callback);
                }
            });
        } else {
            _raw_internal_tcp_socket_connect(sl_peerinfo(host, port), timedout, callback);
        }
    }
}

// Internal write method of a tcp socket
void _raw_internal_tcp_socket_write(sl_event e) 
{
    sl_write_info _wi;
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        auto _wiit = _g_so_write_map.find(e.so);
        if ( _wiit == _g_so_write_map.end() ) return;
        _wi = _wiit->second;
    } while( false );

    sl_shared_write_packet_t _sswpkt;
    do {
        lock_guard<mutex> _(*_wi.locker);
        assert(_wi.packet_queue->size() > 0);
        _sswpkt = _wi.packet_queue->front();
    } while( false );

    //ldebug << "will send data(l:" << _sswpkt->packet.size() << ") to socket " << e.so << ", write mem: " << _wmem << lend;
    while ( _sswpkt->sent_size < _sswpkt->packet.size() ) {
        int _retval = ::send(e.so, 
            _sswpkt->packet.c_str() + _sswpkt->sent_size, 
            (_sswpkt->packet.size() - _sswpkt->sent_size), 
            0 | SL_NETWORK_NOSIGNAL);
        //ldebug << "send return value: " << _retval << lend;
        if ( _retval < 0 ) {
            if ( ENOBUFS == errno || EAGAIN == errno || EWOULDBLOCK == errno ) {
                // No buf
                break;
            } else {
                lerror
                    << "failed to send data on tcp socket: " << e.so 
                    << ", err(" << errno << "): " << ::strerror(errno) << lend;
                // e.event = SL_EVENT_FAILED;
                // sl_socket_close(e.so);
                // if ( _sswpkt->callback ) _sswpkt->callback(e);
                sl_events::server().add_tcpevent(e.so, SL_EVENT_FAILED);
                return;
            }
        } else if ( _retval == 0 ) {
            // No buf? sent 0
            break;
        } else {
            _sswpkt->sent_size += _retval;
        }
    }
    // ldebug << "sent data size " << _sswpkt->sent_size << " to socket " << e.so << lend;

    // Check if has pending data
    do {
        lock_guard<mutex> _(*_wi.locker);
        if ( _sswpkt->sent_size == _sswpkt->packet.size() ) {
            _wi.packet_queue->pop();
        }
        if ( _wi.packet_queue->size() == 0 ) break;

        // Remonitor
        sl_events::server().monitor(e.so, SL_EVENT_WRITE, _raw_internal_tcp_socket_write);
    } while ( false );

    if ( _sswpkt->callback ) _sswpkt->callback(e);
}

/*
    Async send a packet to the peer via current socket.

    @Description
    This method will append the packet to the write queue of the socket,
    then check if current socket is writing or not.
    If is now writing, the method will return directly. Otherwise,
    this method will make the socket to monitor SL_EVENT_WRITE.

    In Linux, this method will always monitor both EPOLLIN and EPOLLOUT
*/
void sl_tcp_socket_send(
    SOCKET_T tso, 
    const string &pkt, 
    sl_socket_event_handler callback
)
{
    if ( pkt.size() == 0 ) return;
    if ( SOCKET_NOT_VALIDATE(tso) ) return;

    //_g_so_write_map
    sl_write_info _wi;
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        auto _wiit = _g_so_write_map.find(tso);
        if ( _wiit == _g_so_write_map.end() ) return;
        _wi = _wiit->second;
    } while( false );

    // Create the new write packet
    shared_ptr<sl_write_packet> _wpkt = make_shared<sl_write_packet>();
    //_wpkt->packet.swap(pkt);
    _wpkt->packet = move(pkt);
    _wpkt->sent_size = 0;
    _wpkt->callback = move(callback);

    do {
        // Lock the write queue
        lock_guard<mutex> _(*_wi.locker);
        _wi.packet_queue->emplace(_wpkt);

        // Just push the packet to the end of the queue
        if ( _wi.packet_queue->size() > 1 ) return;

        // Do monitor
        sl_events::server().monitor(tso, SL_EVENT_WRITE, _raw_internal_tcp_socket_write);
    } while ( false );
}

/*
    Read incoming data from the socket.

    @Description
    This is a block method to read data from the socket.
    
    The socket must be NON_BLOCKING. This method will use a loop
    to fetch all data on the socket till two conditions:
    1. the buffer is not full after current recv action
    2. receive a EAGAIN or EWOULDBLOCK signal

    The method will increase the buffer's size after each loop 
    until reach the max size of string, which should be the size
    of machine memory in default.
*/
bool sl_tcp_socket_read(
    SOCKET_T tso, 
    string& buffer, 
    size_t min_buffer_size
)
{
    if ( SOCKET_NOT_VALIDATE(tso) ) return false;
    
    // Socket must be nonblocking
    buffer.clear();
    buffer.resize(min_buffer_size);
    size_t _received = 0;
    size_t _leftspace = min_buffer_size;

    do {
        int _retCode = ::recv(tso, &buffer[0] + _received, _leftspace, 0 );
        if ( _retCode < 0 ) {
            if ( errno == EINTR ) continue;    // signal 7, retry
            if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
                // No more data on a non-blocking socket
                buffer.resize(_received);
                return true;
            }
            // Other error
            buffer.resize(0);
            lerror << "failed to receive data on tcp socket: " << tso << ", " << ::strerror( errno ) << lend;
            return false;
        } else if ( _retCode == 0 ) {
            // Peer Close
            buffer.resize(0);
            lerror << "the peer has close the socket, recv 0" << lend;
            return false;
        } else {
            _received += _retCode;
            _leftspace -= _retCode;
            if ( _leftspace > 0 ) {
                // Unfull
                buffer.resize(_received);
                return true;
            } else {
                // The buffer is full, try to double the buffer and try again
                if ( min_buffer_size * 2 <= buffer.max_size() ) {
                    min_buffer_size *= 2;
                } else if ( min_buffer_size < buffer.max_size() ) {
                    min_buffer_size = buffer.max_size();
                } else {
                    return true;    // direct return, wait for next read.
                }
                // Resize the buffer and try to read again
                _leftspace = min_buffer_size - _received;
                buffer.resize(min_buffer_size);
            }
        }
    } while ( true );
    return true;
}
/*
    Listen on a tcp port

    @Description
    Listen on a specified tcp port on sepcified interface.
    The bind_port is the listen port info of the method.
    If you want to listen on port 4040 on all interface, set 
    <bind_port> as "0.0.0.0:4040" or sl_peerinfo(INADDR_ANY, 4040).
    If you want to listen only the internal network, like 192.168.1.0/24
    set the <bind_port> like "192.168.1.1:4040"

    The accept callback will return a new incoming socket, which
    has not been monited on any event.
*/
SOCKET_T sl_tcp_socket_listen(
    const sl_peerinfo& bind_port, 
    sl_socket_event_handler accept_callback
)
{
    SOCKET_T tso = _raw_internal_tcp_socket_init();
    if ( SOCKET_NOT_VALIDATE(tso) ) return INVALIDATE_SOCKET;

    // Bind the socket
    struct sockaddr_in _sock_addr;
    memset((char *)&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(bind_port.port_number);
    _sock_addr.sin_addr.s_addr = bind_port.ipaddress;

    sl_events::server().update_handler(tso, SL_EVENT_ACCEPT, [=](sl_event e) {
        SOCKET_T _so = _raw_internal_tcp_socket_init(NULL, NULL, e.so);
        if ( SOCKET_NOT_VALIDATE(_so) ) {
            lerror << "failed to initialize the incoming socket " << e.so << lend;
            sl_socket_close(e.so);
            return;
        }
        accept_callback(e);
    });

    if ( ::bind(tso, (struct sockaddr *)&_sock_addr, sizeof(_sock_addr)) == -1 ) {
        lerror << "failed to listen tcp on " << bind_port << ": " << ::strerror( errno ) << lend;
        sl_socket_close(tso);
        return INVALIDATE_SOCKET;
    }
    if ( -1 == ::listen(tso, 1024) ) {
        lerror << "failed to listen tcp on " << bind_port << ": " << ::strerror( errno ) << lend;
        sl_socket_close(tso);
        return INVALIDATE_SOCKET;
    }
    linfo << "start to listening tcp on " << bind_port << lend;
    if ( !sl_poller::server().bind_tcp_server(tso) ) {
        sl_socket_close(tso);
        return INVALIDATE_SOCKET;
    }
    return tso;
}

/*
    Get original peer info of a socket.

    @Description
    This method will return the original connect peerinfo of a socket
    in Linux with iptables redirect by fetch the info with SO_ORIGINAL_DST
    flag.

    In a BSD(like Mac OS X), will return 0.0.0.0:0
*/
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

void _raw_internal_tcp_redirect_callback(SOCKET_T from_so, SOCKET_T to_so) {
    string _pkt;
    if ( !sl_tcp_socket_read(from_so, _pkt) ) {
        sl_events::server().add_tcpevent(from_so, SL_EVENT_FAILED);
        return;
    }
    sl_tcp_socket_send(to_so, _pkt, [from_so, to_so](sl_event to_event) {
        sl_socket_monitor(
            from_so, 30, 
            bind(_raw_internal_tcp_redirect_callback, from_so, to_so)
        );
    });
}

/*
    Redirect a socket's data to another peer via socks5 proxy.

    @Description
    This method will continuously redirect the data between from_so and the 
    peer side socket. 
    When one side close or drop the connection, this method will close
    both side's sockets.
*/
void sl_tcp_socket_redirect(
    SOCKET_T from_so,
    const sl_peerinfo& peer,
    const sl_peerinfo& socks5
)
{
    sl_tcp_socket_connect(socks5, peer.ipaddress, peer.port_number, 5, [=](sl_event e) {
        if ( e.event != SL_EVENT_CONNECT ) {
            sl_socket_close(from_so);
            return;
        }
        sl_socket_bind_event_failed(e.so, [=](sl_event e) {
            sl_socket_close(from_so);
        });
        sl_socket_bind_event_timeout(e.so, [=](sl_event e) {
            sl_socket_close(e.so);
            sl_socket_close(from_so);
        });
        sl_socket_bind_event_failed(from_so, [=](sl_event fe) {
            sl_socket_close(e.so);
        });
        sl_socket_bind_event_timeout(from_so, [=](sl_event fe) {
            sl_socket_close(e.so);
            sl_socket_close(from_so);
        });

        // Monitor and redirect the data.
        sl_socket_monitor(from_so, 30, bind(_raw_internal_tcp_redirect_callback, from_so, e.so));
        sl_socket_monitor(e.so, 30, bind(_raw_internal_tcp_redirect_callback, e.so, from_so));
    });
}

// UDP Methods
/*
    Initialize a UDP socket

    @Description
    This method will create a UDP socket and bind to the <bind_addr>
    The ipaddress in bind_addr should always be INADDR_ANY.

    As the UDP socket is connectionless, if you want to receive any
    data on specified port, you must set the port at this time.

    In order to get the local infomation of the udp socket,
    the method will bind port 0 to this socket in default.
*/
SOCKET_T sl_udp_socket_init(
    const sl_peerinfo& bind_addr,
    sl_socket_event_handler failed, 
    sl_socket_event_handler timedout
)
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

    // Bind the default handler set.
    sl_handler_set _hset = sl_events::empty_handler();
    _hset.on_failed = [failed](sl_event e) {
        sl_socket_close(e.so);
        if ( failed ) failed(e);
    };
    _hset.on_timedout = [timedout](sl_event e) {
        if ( timedout ) timedout(e);
        else sl_socket_close(e.so);
    };
    sl_events::server().bind(_so, move(_hset));

    // Add A Write Buffer
    sl_write_info _wi = { make_shared<mutex>(), make_shared< queue<sl_shared_write_packet_t> >() };
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        _g_so_write_map[_so] = _wi;
    } while(false);

    return _so;
}
// Internal write method of a udp socket
void _raw_internal_udp_socket_write(sl_event e) 
{
    sl_write_info _wi;
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        auto _wiit = _g_so_write_map.find(e.so);
        if ( _wiit == _g_so_write_map.end() ) return;
        _wi = _wiit->second;
    } while( false );

    sl_shared_write_packet_t _sswpkt;
    do {
        lock_guard<mutex> _(*_wi.locker);
        assert(_wi.packet_queue->size() > 0);
        _sswpkt = _wi.packet_queue->front();
    } while( false );

    struct sockaddr_in _sock_addr = {};
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(_sswpkt->peerinfo.port_number);
    _sock_addr.sin_addr.s_addr = (uint32_t)_sswpkt->peerinfo.ipaddress;

    bool _force_remove_top_packet = false;
    while ( _sswpkt->sent_size < _sswpkt->packet.size() ) {
        int _retval = ::sendto(e.so, 
            _sswpkt->packet.c_str() + _sswpkt->sent_size, 
            (_sswpkt->packet.size() - _sswpkt->sent_size), 
            0 | SL_NETWORK_NOSIGNAL, 
            (struct sockaddr *)&_sock_addr, sizeof(_sock_addr));
        //ldebug << "send return value: " << _retval << lend;
        if ( _retval < 0 ) {
            if ( ENOBUFS == errno || EAGAIN == errno || EWOULDBLOCK == errno ) {
                // No buf
                break;
            } else {
                lerror
                    << "failed to send data on udp socket: " << e.so 
                    << ", err(" << errno << "): " << ::strerror(errno) << lend;
                // e.event = SL_EVENT_FAILED;
                // if ( _sswpkt->callback ) _sswpkt->callback(e);
                sl_events::server().add_udpevent(e.so, _sock_addr, SL_EVENT_FAILED);
                _force_remove_top_packet = true;
                return;
            }
        } else if ( _retval == 0 ) {
            // No buf? sent 0
            break;
        } else {
            _sswpkt->sent_size += _retval;
        }
    }

    // Check if has pending data
    do {
        lock_guard<mutex> _(*_wi.locker);
        if ( _sswpkt->sent_size == _sswpkt->packet.size() || _force_remove_top_packet ) {
            _wi.packet_queue->pop();
        }
        if ( _wi.packet_queue->size() == 0 ) break;

        // Remonitor
        sl_events::server().monitor(e.so, SL_EVENT_WRITE, _raw_internal_udp_socket_write);
    } while ( false );

    if ( _sswpkt->callback ) _sswpkt->callback(e);
}

/*
    Send packet to the peer.

    @Description
    This method is an async send method.
    It will push the packet to the end of the write queue and 
    try to monitor the SL_EVENT_WRITE flag of the socket.
*/
void sl_udp_socket_send(
    SOCKET_T uso,
    const sl_peerinfo& peer,
    const string &pkt,
    sl_socket_event_handler callback
)
{
    if ( pkt.size() == 0 ) return;
    if ( SOCKET_NOT_VALIDATE(uso) ) return;

    //_g_so_write_map
    sl_write_info _wi;
    do {
        lock_guard<mutex> _(_g_so_write_mutex);
        auto _wiit = _g_so_write_map.find(uso);
        if ( _wiit == _g_so_write_map.end() ) return;
        _wi = _wiit->second;
    } while( false );

    // Create the new write packet
    shared_ptr<sl_write_packet> _wpkt = make_shared<sl_write_packet>();
    //_wpkt->packet.swap(pkt);
    _wpkt->packet = move(pkt);
    _wpkt->sent_size = 0;
    _wpkt->peerinfo = peer;
    _wpkt->callback = move(callback);

    do {
        // Lock the write queue
        lock_guard<mutex> _(*_wi.locker);
        _wi.packet_queue->emplace(_wpkt);

        // Just push the packet to the end of the queue
        if ( _wi.packet_queue->size() > 1 ) return;

        // Do monitor
        sl_events::server().monitor(uso, SL_EVENT_WRITE, _raw_internal_udp_socket_write);
    } while ( false );
}

/*
    Block and read data from the UDP socket.

    @Description
    Same as tcp socket read method.
*/
bool sl_udp_socket_read(
    SOCKET_T uso, 
    struct sockaddr_in addr, 
    string& buffer, 
    size_t min_buffer_size
)
{
    if ( SOCKET_NOT_VALIDATE(uso) ) return false;

    sl_peerinfo _pi(addr.sin_addr.s_addr, ntohs(addr.sin_port));

    // Socket must be nonblocking
    buffer.clear();
    buffer.resize(min_buffer_size);
    size_t _received = 0;
    size_t _leftspace = min_buffer_size;

    do {
        unsigned _so_len = sizeof(addr);
        int _retCode = ::recvfrom( uso, &buffer[0], min_buffer_size, 0,
            (struct sockaddr *)&addr, &_so_len);
        if ( _retCode < 0 ) {
            if ( errno == EINTR ) continue;    // signal 7, retry
            if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
                // No more data on a non-blocking socket
                buffer.resize(_received);
                return true;
            }
            // Other error
            buffer.resize(0);
            lerror << "failed to receive data on udp socket: " << uso << "(" << _pi << "), " << ::strerror( errno ) << lend;
            return false;
        } else if ( _retCode == 0 ) {
            // Peer Close
            buffer.resize(0);
            lerror << "the peer has close the socket, recv 0" << lend;
            return false;
        } else {
            _received += _retCode;
            _leftspace -= _retCode;
            if ( _leftspace > 0 ) {
                // Unfull
                buffer.resize(_received);
                return true;
            } else {
                // The buffer is full, try to double the buffer and try again
                if ( min_buffer_size * 2 <= buffer.max_size() ) {
                    min_buffer_size *= 2;
                } else if ( min_buffer_size < buffer.max_size() ) {
                    min_buffer_size = buffer.max_size();
                } else {
                    return true;    // direct return, wait for next read.
                }
                // Resize the buffer and try to read again
                _leftspace = min_buffer_size - _received;
                buffer.resize(min_buffer_size);
            }
        }
    } while ( true );
    return true;
}

/*
    Listen on a UDP port and wait for any incoming data.

    @Description
    As a UDP socket is connectionless, the only different between
    listen and monitor is 'listen' will auto re-monitor the socket
    after a data incoming message has been processed.
*/
void sl_udp_socket_listen(
    SOCKET_T uso, 
    sl_socket_event_handler accept_callback
)
{
    if ( SOCKET_NOT_VALIDATE(uso) ) return;

    auto _listen_callback = [=](sl_event e) {
        lerror << "UDP socket " << e.so << " fetch unexcepted event: " << e << lend;
        // Re-monitor
        sl_udp_socket_listen(uso, accept_callback);
    };
    // Force to update the failed & timeout handler
    sl_events::server().update_handler(uso, SL_EVENT_FAILED | SL_EVENT_TIMEOUT, _listen_callback);

    // Monitor the read event
    sl_socket_monitor(uso, 0, [=](sl_event e) {
        if ( accept_callback ) accept_callback(e);
        #if DEBUG
        ldebug << "after udp socket " << uso << " accept callback, try to re-listen it" << lend;
        #endif
        sl_udp_socket_listen(uso, accept_callback);
    });
}

// Global DNS Server List
vector<sl_peerinfo> _resolv_list;

void _raw_internal_async_gethostname_udp(
    const sl_dns_packet && query_pkt,
    const vector<sl_peerinfo>&& resolv_list,
    size_t use_index,
    async_dns_handler fp
);

void _raw_internal_async_gethostname_tcp(
    const sl_dns_packet && query_pkt,
    const vector<sl_peerinfo>&& resolv_list,
    size_t use_index,
    const sl_peerinfo& socks5,
    async_dns_handler fp
);

void _raw_internal_async_gethostname_udp(
    const sl_dns_packet && query_pkt,
    const vector<sl_peerinfo>&& resolv_list,
    size_t use_index,
    async_dns_handler fp
)
{
    // No other validate resolve ip in the list, return the 255.255.255.255
    if ( resolv_list.size() == use_index ) {
        lwarning << "no more nameserver validated" << lend;
        fp( {sl_ip((uint32_t)-1)} );
        return;
    }

    // Create a new udp socket and send the query packet.
    auto _errorfp = [=](sl_event e) {
        // Assert the event status
        assert(e.event == SL_EVENT_FAILED || e.event == SL_EVENT_TIMEOUT);
        if ( e.event == SL_EVENT_TIMEOUT ) {
            sl_socket_close(e.so);
        }
        // Go next server
        _raw_internal_async_gethostname_udp(
            move(query_pkt), 
            move(resolv_list), 
            use_index + 1,
            fp
        );
    };

    SOCKET_T _uso = sl_udp_socket_init(sl_peerinfo::nan(), _errorfp, _errorfp);

    if ( SOCKET_NOT_VALIDATE(_uso) ) {
        _errorfp(sl_event_make_failed());
        return;
    }

    sl_udp_socket_send(_uso, resolv_list[use_index], query_pkt, [=](sl_event e) {
        sl_socket_monitor(e.so, 1, [=](sl_event e){
            // Read the incoming packet
            string _incoming_pkt;
            bool _ret = sl_udp_socket_read(e.so, e.address, _incoming_pkt);
            // After reading, whether success or not, close the socket first.
            sl_socket_close(e.so);
            if ( !_ret ) {
                // On Failed, go next
                e.event = SL_EVENT_FAILED;
                _errorfp(e);
                return;
            }

            sl_dns_packet _dnspkt(move(_incoming_pkt));
            if ( _dnspkt.get_resp_code() == sl_dns_rcode_noerr ){
                vector<sl_ip> _retval(move(_dnspkt.get_A_records()));
                fp( _retval );
            } else if ( _dnspkt.get_is_truncation() ) {
                // TRUNC flag get, try to use tcp
                _raw_internal_async_gethostname_tcp(
                    move(query_pkt), move(resolv_list), use_index, sl_peerinfo::nan(), fp
                );
            } else {
                // Other error, try next
                _raw_internal_async_gethostname_udp(
                    move(query_pkt), move(resolv_list), use_index + 1, fp
                );
            }
        });
    });
}

void _raw_internal_async_gethostname_tcp(
    const sl_dns_packet && query_pkt,
    const vector<sl_peerinfo>&& resolv_list,
    size_t use_index,
    const sl_peerinfo& socks5,
    async_dns_handler fp
)
{
    // No other validate resolve ip in the list, return the 255.255.255.255
    if ( resolv_list.size() == use_index ) {
        lwarning << "no more nameserver validated" << lend;
        fp( {sl_ip((uint32_t)-1)} );
        return;
    }

    // Create a new udp socket and send the query packet.
    auto _errorfp = [=](sl_event e) {
        // Assert the event status
        assert(e.event == SL_EVENT_FAILED || e.event == SL_EVENT_TIMEOUT);
        // Go next server
        if ( socks5 ) {
            _raw_internal_async_gethostname_tcp(
                move(query_pkt), move(resolv_list), use_index + 1, socks5, fp
            );
        } else {
            _raw_internal_async_gethostname_udp(
                move(query_pkt), move(resolv_list), use_index + 1, fp
            );
        }
    };

    sl_peerinfo _resolv_peer = move(resolv_list[use_index]);

    sl_tcp_socket_connect(socks5, _resolv_peer.ipaddress, _resolv_peer.port_number, 3, [=](sl_event e) {
        if ( e.event != SL_EVENT_CONNECT ) {
            _errorfp(e);
            return;
        }

        // Append error handler to the socket's handler set
        sl_events::server().append_handler(e.so, SL_EVENT_FAILED, _errorfp);
        sl_events::server().append_handler(e.so, SL_EVENT_TIMEOUT, [=](sl_event e){
            sl_socket_close(e.so);
            _errorfp(e);
        });
        sl_tcp_socket_send(e.so, query_pkt.to_tcp_packet(), [=](sl_event e){
            sl_socket_monitor(e.so, 3, [=](sl_event e){
                // Read incoming
                string _tcp_incoming_pkt;
                bool _ret = sl_tcp_socket_read(e.so, _tcp_incoming_pkt);
                // After reading, whether success or not, close the socket first.
                sl_socket_close(e.so);
                if ( !_ret ) {
                    // On Failed, go next
                    e.event = SL_EVENT_FAILED;
                    _errorfp(e);
                    return;
                }
                sl_dns_packet _dnspkt(move(_tcp_incoming_pkt), true);
                if ( _dnspkt.get_resp_code() == sl_dns_rcode_noerr ) {
                    vector<sl_ip> _retval(move(_dnspkt.get_A_records()));
                    fp( _retval );
                } else {
                    // Failed to get the dns result
                    e.event = SL_EVENT_FAILED;
                    _errorfp(e);
                }
            });
        });
    });
}
/*!
    Try to get the dns result async
    @Description
    Use async udp/tcp socket to send a dns query request to the domain name server.
    If has multiple nameserver set in the system, will try all the sever in order
    till the first have a no-error response.
    The method will use a UDP socket at first, if the answer is a TC package, then
    force to send TCP request to the same server again.
    If the server does not response after timeout(5s), will try to use the next
    server in the list.
    If all server failed to answer the query, then will return 255.255.255.255 
    as the IP address of the host to query in the result.

    This method will always return an IP address.
*/
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
            // ldebug << "resolv get dns: " << _pi << lend;
        }
    }
    auto _now = system_clock::now();
    auto _time_point = _now.time_since_epoch();
    _time_point -= duration_cast<seconds>(_time_point); 
    auto _ms = static_cast<unsigned>(_time_point / milliseconds(1));

    sl_dns_packet _pkt((uint16_t)_ms, host);
    _raw_internal_async_gethostname_udp(move(_pkt), move(_resolv_list), 0, fp);
}
/*
    Try to get the dns result async via specified name servers
*/
void sl_async_gethostname(
    const string& host, 
    const vector<sl_peerinfo>& nameserver_list, 
    async_dns_handler fp
)
{
    auto _now = system_clock::now();
    auto _time_point = _now.time_since_epoch();
    _time_point -= duration_cast<seconds>(_time_point); 
    auto _ms = static_cast<unsigned>(_time_point / milliseconds(1));

    sl_dns_packet _pkt((uint16_t)_ms, host);
    _raw_internal_async_gethostname_udp(move(_pkt), move(nameserver_list), 0, fp);
}

/*
    Try to get the dns result via specified name servers through a socks5 proxy.
    THis will force to use tcp connection to the nameserver
*/
void sl_async_gethostname(
    const string& host, 
    const vector<sl_peerinfo>& nameserver_list, 
    const sl_peerinfo &socks5, 
    async_dns_handler fp
)
{
    auto _now = system_clock::now();
    auto _time_point = _now.time_since_epoch();
    _time_point -= duration_cast<seconds>(_time_point); 
    auto _ms = static_cast<unsigned>(_time_point / milliseconds(1));

    sl_dns_packet _pkt((uint16_t)_ms, host);
    if ( socks5 ) {
        _raw_internal_async_gethostname_tcp(move(_pkt), move(nameserver_list), 0, socks5, fp);
    } else {
        _raw_internal_async_gethostname_udp(move(_pkt), move(nameserver_list), 0, fp);
    }
}

/*!
    Redirect a dns query packet to the specified nameserver, and return the 
    dns response packet from the server.
    If specified the socks5 proxy, will force to use tcp redirect.
*/
void sl_async_redirect_dns_query(
    const sl_dns_packet & dpkt,
    const sl_peerinfo &nameserver,
    const sl_peerinfo &socks5,
    bool force_tcp,
    async_dns_redirector fp
)
{
    auto _errorfp = [=]() {
        sl_dns_packet _dpkt(dpkt);
        // This is a response
        _dpkt.set_is_query_request(false);
        _dpkt.set_resp_code(sl_dns_rcode_server_failure);
        if ( fp ) fp(_dpkt);
    };
    if ( socks5 || force_tcp ) {
        sl_tcp_socket_connect(socks5, nameserver.ipaddress, nameserver.port_number, 5, [=](sl_event e) {
            if ( e.event != SL_EVENT_CONNECT ) {
                // Failed
                _errorfp();
                return;
            }
            sl_events::server().append_handler(e.so, SL_EVENT_FAILED | SL_EVENT_TIMEOUT, [=](sl_event e) {
                _errorfp();
            });
            sl_tcp_socket_send(e.so, dpkt.to_tcp_packet(), [=](sl_event e) {
                sl_socket_monitor(e.so, 5, [=](sl_event e) {
                    string _rpkt;
                    if ( !sl_tcp_socket_read(e.so, _rpkt) ) {
                        sl_socket_close(e.so);
                        _errorfp();
                        return;
                    }
                    sl_socket_close(e.so);
                    sl_dns_packet _dpkt(_rpkt, true);
                    if ( fp ) fp(_dpkt);
                });
            });
        });
    } else {
        SOCKET_T _uso = sl_udp_socket_init();
        sl_events::server().append_handler(_uso, SL_EVENT_FAILED | SL_EVENT_TIMEOUT, [=](sl_event e) {
            _errorfp();
        });
        sl_udp_socket_send(_uso, nameserver, dpkt, [=](sl_event e) {
            sl_socket_monitor(_uso, 3, [=](sl_event e) {
                string _rpkt;
                if ( !sl_udp_socket_read(e.so, e.address, _rpkt) ) {
                    sl_socket_close(e.so);
                    _errorfp();
                    return;
                }
                sl_socket_close(e.so);
                sl_dns_packet _dpkt(_rpkt);
                if ( fp ) fp(_dpkt);
            });
        });
    }
}
/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// End of amalgamate file
