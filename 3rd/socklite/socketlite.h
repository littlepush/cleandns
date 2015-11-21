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

// Current Version: 0.5-9-gc737c50

#pragma once
// inc/socket.h
#ifndef __SOCK_LITE_SOCKET_H__
#define __SOCK_LITE_SOCKET_H__

#if ( defined WIN32 | defined _WIN32 | defined WIN64 | defined _WIN64 )
    #define _SL_PLATFORM_WIN      1
#elif TARGET_OS_WIN32
    #define _SL_PLATFORM_WIN      1
#elif defined __CYGWIN__
    #define _SL_PLATFORM_WIN      1
#else
    #define _SL_PLATFORM_WIN      0
#endif
#ifdef __APPLE__
    #define _SL_PLATFORM_MAC      1
#else
    #define _SL_PLATFORM_MAC      0
#endif
#if _SL_PLATFORM_WIN == 0 && _SL_PLATFORM_MAC == 0
    #define _SL_PLATFORM_LINUX    1
#else
    #define _SL_PLATFORM_LINUX    0
#endif
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    #define _SL_PLATFORM_IOS      1
#else
    #define _SL_PLATFORM_IOS      0
#endif

#define SL_TARGET_WIN32  (_SL_PLATFORM_WIN == 1)
#define SL_TARGET_LINUX  (_SL_PLATFORM_LINUX == 1)
#define SL_TARGET_MAC    (_SL_PLATFORM_MAC == 1)
#define SL_TARGET_IOS    (_SL_PLATFORM_IOS == 1)

#if SL_TARGET_WIN32
// Disable the certain warn in Visual Studio for old functions.
#pragma warning (disable : 4996)
#pragma warning (disable : 4251)

#endif

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <wchar.h>
#include <wctype.h>
#include <stddef.h>
#include <math.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <sys/stat.h>

#include <iostream>
#include <string>
using namespace std;

#if SL_TARGET_WIN32
#include <WinSock2.h>
#include <Windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <stddef.h>
#include <sys/time.h>
#endif

// Linux Thread, pit_t
#if SL_TARGET_LINUX
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#define gettid()    syscall(__NR_gettid)
#endif

// For Mac OS X
#ifdef __APPLE__
#include <libkern/OSAtomic.h>
#include <unistd.h>
#include <sys/syscall.h>
#define gettid()    syscall(SYS_gettid)
#endif

#if SL_TARGET_WIN32
    #include <WS2tcpip.h>
    #pragma comment( lib, "Ws2_32.lib" )
    #define SL_NETWORK_NOSIGNAL           0
    #define SL_NETWORK_IOCTL_CALL         ioctlsocket
    #define SL_NETWORK_CLOSESOCK          ::closesocket
#else 
    #include <sys/socket.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <netinet/tcp.h>
    #define SL_NETWORK_NOSIGNAL           MSG_NOSIGNAL
    #define SL_NETWORK_IOCTL_CALL         ioctl
    #define SL_NETWORK_CLOSESOCK          ::close
#endif

#if SL_TARGET_MAC
    #undef  SL_NETWORK_NOSIGNAL
    #define SL_NETWORK_NOSIGNAL           0
#endif

typedef enum {
    SO_INVALIDATE       = -1,
    SO_IDLE             = 0,
    SO_OK               = 1
} SOCKETSTATUE;

typedef enum {
	SO_READ_WAITING		= 0x0000,
	SO_READ_CLOSE		= 0x0001,	// recv return code < 0
	SO_READ_TIMEOUT		= 0x0002,	// select time out
	SO_READ_DONE		= 0x0004,	// get incoming data
	SO_READ_TIMEOUT_AND_UNFINISH	= SO_READ_DONE | SO_READ_TIMEOUT,
	SO_READ_DONE_BUT_CLOSED			= SO_READ_DONE | SO_READ_CLOSE,
} SO_READ_STATUE;

typedef enum {
    SO_CHECK_WRITE      = 1,
    SO_CHECK_READ       = 2,
    SO_CHECK_CONNECT    = SO_CHECK_WRITE | SO_CHECK_READ
} SOCKETOPT;

typedef long SOCKET_T;

#ifndef INVALIDATE_SOCKET
#define INVALIDATE_SOCKET           ((long)((long)0 - (long)1))
#endif

#define SOCKET_NOT_VALIDATE( so )   ((so) == INVALIDATE_SOCKET)
#define SOCKET_VALIDATE( so )       ((so) != INVALIDATE_SOCKET)

// In No-Windows
#ifndef FAR
#define FAR
#endif

#ifndef __SOCKET_SERVER_INIT_IN_WINDOWS__
#define __SOCKET_SERVER_INIT_IN_WINDOWS__
#if SL_TARGET_WIN32

// In Windows Only.
// This class is used to initialize the WinSock Server.
// A global instance of this object will be create and
// provide nothing. only the c'str of this object
// will invoke WSAStartup and the d'str will invoke 
// WSACleanup.
// In Linux or other platform, this object will not be
// defined.
template< int __TMP_VALUE__ = 0 >
class __socket_init_svr_in_windows
{
    __socket_init_svr_in_windows< __TMP_VALUE__ >()
    {
        WSADATA v_wsaData;
        WORD v_wVersionRequested;

        v_wVersionRequested = MAKEWORD(1, 1);
        WSAStartup(v_wVersionRequested, &v_wsaData);
    }

public:
    ~__socket_init_svr_in_windows< __TMP_VALUE__ >()
    {
        WSACleanup();
    }
    static __socket_init_svr_in_windows< __TMP_VALUE__ > __g_socksvrInWindows;
};

template< > __socket_init_svr_in_windows< 0 > 
__socket_init_svr_in_windows< 0 >::__g_socksvrInWindows;

#endif
#endif

// Translate Domain to IP Address
char * network_domain_to_ip(const char * domain, char * output, unsigned int length);

// Translate Domain to InAddr
unsigned int network_domain_to_inaddr(const char * domain);

// Translate the ip string to an InAddr
uint32_t network_ipstring_to_inaddr(const string &ipaddr);

// Translate the InAddr to an Ip string
void network_inaddr_to_string(uint32_t inaddr, string &ipstring);

// Get localhost's computer name on LAN.
void network_get_localhost_name( string &hostname );

// Convert the uint ip addr to human readable ip string.
void network_int_to_ipaddress( const uint32_t ipaddr, string &ip );

// Get peer ipaddress and port from a specified socket handler.
void network_peer_info_from_socket( const SOCKET_T hSo, uint32_t &ipaddr, uint32_t &port );

// Get current socket's port info
void network_sock_info_from_socket( const SOCKET_T hSo, uint32_t &port );

// Check the specified socket's status according to the option.
SOCKETSTATUE socket_check_status( SOCKET_T hSo, SOCKETOPT option = SO_CHECK_READ, uint32_t waitTime = 0 );

// Set the linger time for a socket, I strong suggest not to change this value unless you 
// know what you are doing
bool socket_set_linger_time(SOCKET_T so, bool onoff = true, unsigned timeout = 1);

/*!
The IP object, compatible with std::string and uint32_t
This is a ipv4 ip address class.
*/
class sl_ip {
    string          ip_;

public:
    sl_ip();
    sl_ip(const sl_ip& rhs);

    // Conversition
    sl_ip(const string &ipaddr);
    sl_ip(uint32_t ipaddr);
    operator uint32_t() const;
    operator string&();
    operator string() const;
    operator const string&() const;
    operator const char *() const;
    const char *c_str() const;
    size_t size() const;

    // Cast operator
    sl_ip & operator = (const string &ipaddr);
    sl_ip & operator = (uint32_t ipaddr);

    // Operators
    bool operator == (const sl_ip& rhs) const;
    bool operator != (const sl_ip& rhs) const;
    bool operator <(const sl_ip& rhs) const;
    bool operator >(const sl_ip& rhs) const;
    bool operator <=(const sl_ip& rhs) const;
    bool operator >=(const sl_ip& rhs) const;
};

// Output
ostream & operator << (ostream &os, const sl_ip & ip);

/*!
Peer Info, contains an IP address and a port number.
should be output in the following format: 0.0.0.0:0
*/
class sl_peerinfo {
    sl_ip           ip_;
    uint16_t        port_;
    string          format_;
public:
    const sl_ip &       ipaddress;
    const uint16_t &    port_number;

    void parse_peerinfo_from_string(const string &format_string);
    void set_peerinfo(const string &ipaddress, uint16_t port);
    void set_peerinfo(uint32_t inaddr, uint16_t port);

    sl_peerinfo();
    sl_peerinfo(uint32_t inaddr, uint16_t port);
    sl_peerinfo(const string &format_string);
    sl_peerinfo(const string &ipaddr, uint16_t port);
    sl_peerinfo(const sl_peerinfo& rhs);
    sl_peerinfo & operator = (const sl_peerinfo& rhs);
    sl_peerinfo & operator = (const string &format_string);

    operator bool() const;
    operator const string () const;
    operator const char *() const;
    const char *c_str() const;
    size_t size() const;
};

// Output the peer info
ostream & operator << (ostream &os, const sl_peerinfo &peer);


// The basic virtual socket class
class sl_socket
{
protected:
    bool m_iswrapper;
public:
    // The socket handler
    SOCKET_T  m_socket;

    sl_socket(bool iswrapper = false);
    virtual ~sl_socket();
    // Connect to peer
    virtual bool connect( const uint32_t inaddr, uint32_t port, uint32_t timeout = 1000 ) = 0;
    virtual bool connect( const sl_ip& ip, uint32_t port, uint32_t timeout = 1000 ) = 0;
    virtual bool connect( const sl_peerinfo &peer, uint32_t timeout = 1000 ) = 0;
    virtual bool connect( const string &ipaddr, uint32_t port, uint32_t timeout = 1000 ) = 0;
    // Listen on specified port and address, default is 0.0.0.0
    virtual bool listen( uint32_t port, uint32_t ipaddr = INADDR_ANY ) = 0;
    // Close the connection
    void close();
    // When the socket is a listener, use this method 
    // to accept client's connection.
    //virtual sl_socket *get_client( uint32_t timeout = 100 ) = 0;
    //virtual void release_client( sl_socket *client ) = 0;

    // Set current socket reusable or not
    bool set_reusable( bool reusable = true );
    // Enable TCP_KEEPALIVE or not
    bool set_keepalive( bool keepalive = true );
    // Set the socket to be non-block
    bool set_nonblocking( bool nonblocking = true );
    // Set socket buffer, 0 means remine default
    bool set_socketbufsize( unsigned int rmem = 0, unsigned int wmem = 0 );

    // Read data from the socket until timeout or get any data.
    virtual SO_READ_STATUE read_data( string &buffer, uint32_t timeout = 1000 ) = 0;

    // Write data to peer.
    virtual bool write_data( const string &data ) = 0;
};

#endif 

// inc/socks5.h
#ifndef __SOCKLITE_SOCKS_5_H__
#define __SOCKLITE_SOCKS_5_H__


#include <functional>

enum sl_methods {
	sl_method_noauth		= 0,
	sl_method_gssapi		= 1,
	sl_method_userpwd		= 2,
	sl_method_nomethod		= 0xff
};

enum sl_socks5cmd {
	sl_socks5cmd_connect	= 1,
	sl_socks5cmd_bind		= 2,
	sl_socks5cmd_udp		= 3
};

enum sl_socks5atyp {
	sl_socks5atyp_ipv4		= 1,
	sl_socks5atyp_dname		= 3,
	sl_socks5atyp_ipv6		= 4,
};

enum sl_socks5rep {
	sl_socks5rep_successed			= 0,	// successed
	sl_socks5rep_failed				= 1,	// general SOCKS server failure
	sl_socks5rep_connectnotallow	= 2,	// connection not allowed by ruleset
	sl_socks5rep_unreachable		= 3,	// Network unreachable
	sl_socks5rep_hostunreachable	= 4,	// Host unreachable
	sl_socks5rep_refused			= 5,	// Connection refused
	sl_socks5rep_expired			= 6,	// TTL expired
	sl_socks5rep_notsupport			= 7,	// Command not supported
	sl_socks5rep_erroraddress		= 8,	// Address type not supported
};

static inline const char *sl_socks5msg(sl_socks5rep rep) {
	static const char * _gmsg[] = {
		"successed",
		"general SOCKS server failure",
		"connection not allowed by ruleset",
		"Network unreachable",
		"Host unreachable",
		"Connection refused",
		"TTL expired",
		"Command not supported",
		"Address type not supported",
		"Unknow Error Code"
	};
	if ( rep > sl_socks5rep_erroraddress ) return _gmsg[sl_socks5rep_erroraddress + 1];
	return _gmsg[rep];
};

#pragma pack(push, 1)
struct sl_socks5_package {
	uint8_t 	ver;

	// Default we only support version 5
	sl_socks5_package() : ver(5) {}
};

struct sl_socks5_handshake_request : public sl_socks5_package {
	uint8_t		nmethods;
};

struct sl_socks5_noauth_request : public sl_socks5_handshake_request {
	uint8_t 	method;

	sl_socks5_noauth_request(): 
		sl_socks5_handshake_request(), method(sl_method_noauth) {
		nmethods = 1;
		}
};

struct sl_socks5_gssapi_request : public sl_socks5_handshake_request {
	uint8_t		method;

	sl_socks5_gssapi_request():
		sl_socks5_handshake_request(), method(sl_method_gssapi) {
		nmethods = 1;
		}
};

struct sl_socks5_userpwd_request : public sl_socks5_handshake_request {
	uint8_t		method;

	sl_socks5_userpwd_request():
		sl_socks5_handshake_request(), method(sl_method_userpwd) {
		nmethods = 1;
		}
};

struct sl_socks5_handshake_response : public sl_socks5_package {
	uint8_t		method;

	sl_socks5_handshake_response() : sl_socks5_package() {}
	sl_socks5_handshake_response(sl_methods m) : sl_socks5_package(), method(m) { }
};

struct sl_socks5_connect_request : public sl_socks5_package {
	uint8_t		cmd;
	uint8_t		rsv;	// reserved
	uint8_t		atyp;	// address type

	sl_socks5_connect_request():
		sl_socks5_package(), cmd(sl_socks5cmd_connect), rsv(0) {}
};

struct sl_socks5_ipv4_request : public sl_socks5_connect_request {
	uint32_t	ip;
	uint16_t	port;

	sl_socks5_ipv4_request(uint32_t ipv4, uint16_t p):
		sl_socks5_connect_request(), ip(ipv4), port(p) {
		atyp = sl_socks5atyp_ipv4;
		}
};

struct sl_socks5_connect_response : public sl_socks5_package {
	uint8_t		rep;
	uint8_t		rsv;
	uint8_t		atyp;

	sl_socks5_connect_response() : sl_socks5_package() {}
};

struct sl_socks5_ipv4_response : public sl_socks5_connect_response {
	uint32_t	ip;
	uint16_t	port;

	sl_socks5_ipv4_response(): sl_socks5_connect_response() {}
	sl_socks5_ipv4_response(uint32_t addr, uint16_t p):
		sl_socks5_connect_response(), 
		ip(addr),
		port(p)
	{
	rep = sl_socks5rep_successed;
	atyp = sl_socks5atyp_ipv4;
	}
};
#pragma pack(pop)

// The function point to auth a connection by username and password
//typedef bool (*sl_auth_method)(const string&, const string&);
using sl_auth_method = function<bool(const string &, const string &)>;

// Setup the supported methods, can be invoke multiple times
void sl_socks5_set_supported_method(sl_methods m);

// Hand shake the new connection, if return nomethod, than should close the connection
sl_methods sl_socks5_handshake_handler(SOCKET_T so);

// Auth the connection by username and password
bool sl_socks5_auth_by_username(SOCKET_T so, sl_auth_method auth);

// Try to get the connection info
bool sl_socks5_get_connect_info(SOCKET_T so, string &addr, uint16_t& port);

// Failed to connect to peer
void sl_socks5_failed_connect_to_peer(SOCKET_T so, sl_socks5rep rep);

// After connect to peer, send a response to the incoming connection
void sl_socks5_did_connect_to_peer(SOCKET_T so, uint32_t addr, uint16_t port);

#endif // socklite.socks5.h

// inc/poller.h
#ifndef __SOCK_LITE_POLLER_H__
#define __SOCK_LITE_POLLER_H__


#if SL_TARGET_LINUX
#include <sys/epoll.h>
#elif SL_TARGET_MAC
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>
#endif

#include <vector>
#include <map>

#define CO_MAX_SO_EVENTS		1024

enum SL_EVENT_ID {
	SL_EVENT_ACCEPT			= 0,
	SL_EVENT_DATA			= 1,
	SL_EVENT_FAILED			= 2
};

typedef struct tag_sl_event {
	SOCKET_T				so;
	SOCKET_T				source;
	SL_EVENT_ID				event;
	int						socktype;
    struct sockaddr_in      address;    // For UDP socket usage.
} sl_event;

class sl_poller
{
public:
	typedef std::vector<sl_event>	earray;
protected:
	int 				m_fd;
#if SL_TARGET_LINUX
	struct epoll_event	*m_events;
#elif SL_TARGET_MAC
	struct kevent		*m_events;
#endif

	std::map<SOCKET_T, bool>	m_tcp_svr_map;
	std::map<SOCKET_T, bool>	m_udp_svr_map;

protected:
	sl_poller();
public:
	~sl_poller();

	// Bind the server side socket
	void bind_tcp_server( SOCKET_T so );
	void bind_udp_server( SOCKET_T so );

	// Try to fetch new events
	size_t fetch_events( earray &events,  unsigned int timedout = 1000 );

	// Start to monitor a socket hander
	// In default, the poller will maintain the socket infinite, if
	// `oneshot` is true, then will add the ONESHOT flag
	void monitor_socket( SOCKET_T so, bool oneshot = false, bool isreset = false );

	// Singleton Poller Item
	static sl_poller &server();
};

#endif

// inc/tcpsocket.h
#ifndef __SOCK_LITE_TCPSOCKET_H__
#define __SOCK_LITE_TCPSOCKET_H__


// Tcp socket for clean dns use.
class sl_tcpsocket : public sl_socket
{
protected:
    bool m_is_connected_to_proxy;

    // Internal connect to peer
    bool _internal_connect( uint32_t inaddr, uint32_t port, uint32_t timeout = 1000 );
    bool _internal_connect( const string &ipaddr, uint32_t port, uint32_t timeout = 1000 );
public:
    sl_tcpsocket(bool iswrapper = false);
	sl_tcpsocket(SOCKET_T so, bool iswrapper = true);
    virtual ~sl_tcpsocket();

    // Set up a socks5 proxy.
    bool setup_proxy( const string &socks5_addr, uint32_t socks5_port );
	bool setup_proxy( const string &socks5_addr, uint32_t socks5_port,
			const string &username, const string &password);
    // Connect to peer
    virtual bool connect( const uint32_t inaddr, uint32_t port, uint32_t timeout = 1000 );
    virtual bool connect( const sl_ip& ip, uint32_t port, uint32_t timeout = 1000 );
    virtual bool connect( const sl_peerinfo &peer, uint32_t timeout = 1000 );
    virtual bool connect( const string &ipaddr, uint32_t port, uint32_t timeout = 1000 );
    // Listen on specified port and address, default is 0.0.0.0
    virtual bool listen( uint32_t port, uint32_t ipaddr = INADDR_ANY );

    // Try to get the original destination, this method now only work under linux
    bool get_original_dest( string &address, uint32_t &port );

    // Read data from the socket until timeout or get any data.
    virtual SO_READ_STATUE read_data( string &buffer, uint32_t timeout = 1000 );

	// Only try to read data once, the socket must receive SL_EVENT_DATA by the poller
	SO_READ_STATUE recv(string &buffer, unsigned int max_buffer_len = 512);

    // Write data to peer.
    virtual bool write_data( const string &data );
};

#endif

// inc/udpsocket.h
#ifndef __SOCK_LITE_UDPSOCKET_H__
#define __SOCK_LITE_UDPSOCKET_H__


// UDP socket
class sl_udpsocket : public sl_socket
{
public:
    struct sockaddr_in m_sock_addr;

    sl_udpsocket(bool iswrapper = false);
    sl_udpsocket(SOCKET_T so);
    sl_udpsocket(SOCKET_T so, struct sockaddr_in addr);

    virtual ~sl_udpsocket();

    // The IP Address information for peer socket
    string & ipaddress( string & ipstr ) const;
    // The Port of peer socket
    uint32_t port() const;

    // Connect to peer
    virtual bool connect( const uint32_t inaddr, uint32_t port, uint32_t timeout = 1000 );
    virtual bool connect( const sl_ip& ip, uint32_t port, uint32_t timeout = 1000 );
    virtual bool connect( const sl_peerinfo &peer, uint32_t timeout = 1000 );
    virtual bool connect( const string &ipaddr, uint32_t port, uint32_t timeout = 1000 );
    // Listen on specified port and address, default is 0.0.0.0
    virtual bool listen( uint32_t port, uint32_t ipaddr = INADDR_ANY );

    // Read data from the socket until timeout or get any data.
    virtual SO_READ_STATUE read_data( string &buffer, uint32_t timeout = 1000 );
    // Only try to read data once, the socket must receive SL_EVENT_DATA by the poller
    SO_READ_STATUE recv(string &buffer, unsigned int max_buffer_len = 512);
    // Write data to peer.
    virtual bool write_data( const string &data );
};

#endif

// sock.lite.h

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
// End of amalgamate file
