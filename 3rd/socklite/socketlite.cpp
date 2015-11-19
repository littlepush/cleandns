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

// Current Version: 0.5-1-gd084051

#include "socketlite.h"
// src/socket.cpp
// #include <execinfo.h>

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

sl_socket::sl_socket(bool iswrapper) : m_iswrapper(iswrapper), m_socket(INVALIDATE_SOCKET) { }

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

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */

// src/poller.cpp

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

void sl_poller::bind_tcp_server( SOCKET_T so ) {
	m_tcp_svr_map[so] = true;
	unsigned long _u = 1;
	SL_NETWORK_IOCTL_CALL(so, FIONBIO, &_u);
#if SL_TARGET_LINUX
	struct epoll_event _e;
	_e.data.fd = so;
	_e.events = EPOLLIN | EPOLLET;
	epoll_ctl( m_fd, EPOLL_CTL_ADD, so, &_e );
#elif SL_TARGET_MAC
	struct kevent _e;
	EV_SET(&_e, so, EVFILT_READ, EV_ADD, 0, 0, NULL);
	kevent(m_fd, &_e, 1, NULL, 0, NULL);
#endif
}

void sl_poller::bind_udp_server( SOCKET_T so ) {
	m_udp_svr_map[so] = true;
	unsigned long _u = 1;
	SL_NETWORK_IOCTL_CALL(so, FIONBIO, &_u);
#if SL_TARGET_LINUX
	struct epoll_event _e;
	_e.data.fd = so;
	_e.events = EPOLLIN | EPOLLET;
	epoll_ctl( m_fd, EPOLL_CTL_ADD, so, &_e );
#elif SL_TARGET_MAC
	struct kevent _e;
	EV_SET(&_e, so, EVFILT_READ, EV_ADD, 0, 0, NULL);
	kevent(m_fd, &_e, 1, NULL, 0, NULL);
#endif
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
			int _error = 0, _len = sizeof(int);
			getsockopt( _e.so, SOL_SOCKET, SO_ERROR, 
					(char *)&_error, (socklen_t *)&_len);
			_e.event = (_error != 0) ? SL_EVENT_FAILED : SL_EVENT_DATA;
			
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

void sl_poller::monitor_socket( SOCKET_T so, bool oneshot, bool isreset ) {
	if ( m_fd == -1 ) return;
#if SL_TARGET_LINUX

	// Socket must be nonblocking
	unsigned long _u = 1;
	SL_NETWORK_IOCTL_CALL(so, FIONBIO, &_u);

	struct epoll_event _ee;
	_ee.data.fd = so;
	_ee.events = EPOLLIN | EPOLLET;
	int _op = EPOLL_CTL_ADD;
	if ( oneshot ) {
		_ee.events |= EPOLLONESHOT;
		if ( isreset ) _op = EPOLL_CTL_MOD;
	}
	epoll_ctl( m_fd, _op, so, &_ee );
#elif SL_TARGET_MAC
	struct kevent _ke;
	unsigned short _flags = EV_ADD;
	if ( oneshot ) {
		_flags |= EV_ONESHOT;
	}
	EV_SET(&_ke, so, EVFILT_READ, _flags, 0, 0, NULL);
	kevent(m_fd, &_ke, 1, NULL, 0, NULL);
#endif
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
bool sl_tcpsocket::_internal_connect( const string &ipaddr, uint32_t port, uint32_t timeout )
{
    if ( ipaddr.size() == 0 || port == 0 || port >= 65535 ) return false;
    
    const char *_addr = ipaddr.c_str();
    uint32_t _timeout = timeout;

    // Try to nslookup the host
    unsigned int _in_addr = network_domain_to_inaddr( _addr );
    if ( _in_addr == (unsigned int)(-1) ) {
        return false;
    }

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
    _sock_addr.sin_addr.s_addr = _in_addr;
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(port);

    // Async Socket Connecting
    unsigned long _u = 1;
    SL_NETWORK_IOCTL_CALL(m_socket, FIONBIO, &_u);

    // Connect
    if ( ::connect( m_socket, (struct sockaddr *)&_sock_addr, 
            sizeof(_sock_addr) ) == -1 )
    {
        struct timeval _tm = { _timeout / 1000, 
            static_cast<int>((_timeout % 1000) * 1000) };
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
    return true;
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

// End of amalgamate file
