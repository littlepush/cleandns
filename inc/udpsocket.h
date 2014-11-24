/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : udpsocket.h
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

#ifndef __CLEAN_DNS_UDPSOCKET_H__
#define __CLEAN_DNS_UDPSOCKET_H__

#include "config.h"
#include "socket.h"

// UDP socket
class cleandns_udpsocket
{
protected:
    char m_buffer[1024];
public:
    // The socket handler
    SOCKET_T m_socket;
    SOCKET_T m_parent; 
    struct sockaddr_in m_sock_addr;
    socklen_t m_so_len;
    string m_data;

    cleandns_udpsocket();
    ~cleandns_udpsocket();

    // Connect to peer
    bool connect( const string &ipaddr, u_int32_t port );
    // Listen on specified port and address, default is 0.0.0.0
    bool listen( u_int32_t port, u_int32_t ipaddr = INADDR_ANY );
    // Close the connection
    void close();
    // When the socket is a listener, use this method 
    // to accept client's connection.
    cleandns_udpsocket *get_client( u_int32_t timeout = 100 );

    // Set current socket reusable or not
    bool set_reusable( bool reusable = true );

    // Read data from the socket until timeout or get any data.
    bool read_data( string &buffer, u_int32_t timeout = 1000 );
    // Write data to peer.
    bool write_data( const string &data );
};

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */