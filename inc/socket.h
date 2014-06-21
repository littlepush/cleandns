/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : socket.h
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

#ifndef __CLEAN_DNS_SOCKET_H__
#define __CLEAN_DNS_SOCKET_H__

#include "config.h"
#if _DEF_WIN32
    #include <WS2tcpip.h>
    #pragma comment( lib, "Ws2_32.lib" )
    #define CLEANDNS_NETWORK_NOSIGNAL           0
    #define CLEANDNS_NETWORK_IOCTL_CALL         ioctlsocket
    #define CLEANDNS_NETWORK_CLOSESOCK          ::closesocket
#else 
    #include <sys/socket.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <netinet/tcp.h>
    #define CLEANDNS_NETWORK_NOSIGNAL           MSG_NOSIGNAL
    #define CLEANDNS_NETWORK_IOCTL_CALL         ioctl
    #define CLEANDNS_NETWORK_CLOSESOCK          ::close
#endif

#if _DEF_MAC
    #undef  CLEANDNS_NETWORK_NOSIGNAL
    #define CLEANDNS_NETWORK_NOSIGNAL           0
#endif

typedef enum {
    SO_INVALIDATE       = -1,
    SO_IDLE             = 0,
    SO_OK               = 1
} SOCKETSTATUE;

typedef enum {
    SO_CHECK_WRITE      = 1,
    SO_CHECK_READ       = 2,
    SO_CHECK_CONNECT    = 4
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
#if _DEF_WIN32

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

// Get localhost's computer name on LAN.
void network_get_localhost_name( string &hostname );

// Convert the uint ip addr to human readable ip string.
void network_int_to_ipaddress( const u_int32_t ipaddr, string &ip );

// Get peer ipaddress and port from a specified socket handler.
void network_peer_info_from_socket( const SOCKET_T hSo, u_int32_t &ipaddr, u_int32_t &port );

// Check the specified socket's status according to the option.
SOCKETSTATUE socket_check_status( SOCKET_T hSo, SOCKETOPT option = SO_CHECK_READ, u_int32_t waitTime = 0 );

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */