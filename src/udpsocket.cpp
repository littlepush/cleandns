/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : udpsocket.cpp
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

#include "udpsocket.h"

cleandns_udpsocket::cleandns_udpsocket()
: m_socket(INVALIDATE_SOCKET), m_parent(INVALIDATE_SOCKET)
{
    // nothing
}
cleandns_udpsocket::~cleandns_udpsocket()
{
    this->close();
}

// Connect to peer
bool cleandns_udpsocket::connect( const string &ipaddr, u_int32_t port )
{
    memset( &m_sock_addr, 0, sizeof(m_sock_addr) );
    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(port);
    if ( inet_aton(ipaddr.c_str(), &m_sock_addr.sin_addr) == 0 ) {
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
bool cleandns_udpsocket::listen( u_int32_t port, u_int32_t ipaddr )
{
    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;
    memset((char *)&m_sock_addr, 0, sizeof(m_sock_addr));

    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(port);
    m_sock_addr.sin_addr.s_addr = htonl(ipaddr);
    if ( bind(m_socket, (struct sockaddr *)&m_sock_addr, sizeof(m_sock_addr)) == -1 ) {
        CLEANDNS_NETWORK_CLOSESOCK(m_socket);
        return false;
    }
    return true;
}
// Close the connection
void cleandns_udpsocket::close()
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return;
    CLEANDNS_NETWORK_CLOSESOCK(m_socket);
    m_socket = INVALIDATE_SOCKET;
}
// When the socket is a listener, use this method 
// to accept client's connection.
cleandns_udpsocket *cleandns_udpsocket::get_client( u_int32_t timeout )
{
    if ( m_socket == INVALIDATE_SOCKET ) return NULL;

    // Set recv timeout
    struct timeval _tv = { timeout / 1000, timeout % 1000 * 1000 };
    if ( setsockopt( m_socket, SOL_SOCKET, SO_RCVTIMEO, &_tv, sizeof(_tv) ) == -1 ) return NULL;

    // Wait to receive data.
    int _buffer_len = 1024;

    // create new socket client
    cleandns_udpsocket *_new_client = new cleandns_udpsocket;

    int _data_len = ::recvfrom( m_socket, m_buffer, _buffer_len, 0,
        (struct sockaddr *)&_new_client->m_sock_addr, 
        &_new_client->m_so_len);
    //PINFO("Data Len: " << _dataLen);
    if ( _data_len <= 0 ) {
        // No data.
        delete _new_client;
        return NULL;
    }

    _new_client->m_data.append(m_buffer, _data_len);
    _new_client->m_parent = m_socket;

    return _new_client;
}

// Set current socket reusable or not
bool cleandns_udpsocket::set_reusable( bool reusable )
{
    if ( m_socket == INVALIDATE_SOCKET ) return false;
    int _reused = reusable ? 1 : 0;
    return setsockopt( m_socket, SOL_SOCKET, SO_REUSEADDR,
        (const char *)&_reused, sizeof(int) ) != -1;
}

// Read data from the socket until timeout or get any data.
bool cleandns_udpsocket::read_data( string &buffer, u_int32_t timeout )
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;

    // Set the receive time out
    struct timeval _tv = { timeout / 1000, timeout % 1000 * 1000 };
    if ( setsockopt( m_socket, SOL_SOCKET, SO_RCVTIMEO, &_tv, sizeof(_tv) ) == -1)
        return false;

    buffer = "";
    int _data_len = 0;
    do {
        m_so_len = sizeof(m_sock_addr);
        _data_len = ::recvfrom( m_socket, m_buffer, 1024, 0,
            (struct sockaddr *)&m_sock_addr, &m_so_len);
        if ( _data_len > 0 ) {
            buffer.append( m_buffer, _data_len );
        }
        if ( _data_len == 1024 ) // m_buffer is full, so maybe still has data
            continue;
        break;
    } while( true );

    return (_data_len >= 0);
}
// Write data to peer.
bool cleandns_udpsocket::write_data( const string &data )
{
    if ( data.size() == 0 ) return false;
    if ( SOCKET_NOT_VALIDATE(m_socket) ) {
        if ( SOCKET_NOT_VALIDATE(m_parent) ) return false;
        // Re-Write to parent
        return (::sendto( m_parent, data.c_str(), data.size(), 
            0, (struct sockaddr *)&m_sock_addr, m_so_len) > 0);
    } else {
        int _allSent = 0;
        int _lastSent = 0;

        u_int32_t _length = data.size();
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
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */