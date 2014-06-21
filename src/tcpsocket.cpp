/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : tcpsocket.cpp
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

#include "tcpsocket.h"

cleandns_tcpsocket::cleandns_tcpsocket()
:_svrfd(NULL), m_socket(INVALIDATE_SOCKET)
{
    // Nothing
}
cleandns_tcpsocket::~cleandns_tcpsocket()
{
    this->close();
}

// Connect to peer
bool cleandns_tcpsocket::connect( const string &ipaddr, u_int32_t port )
{
    if ( ipaddr.size() == 0 || port == 0 || port >= 65535 ) return false;
    
    const char *_addr = ipaddr.c_str();
    u_int32_t _timeout = 1000;

    // Try to nslookup the host
    unsigned int _in_addr = inet_addr( _addr );
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
        CLEANDNS_NETWORK_CLOSESOCK( m_socket );
        return false;
    }

    struct sockaddr_in _sock_addr; 
    memset( &_sock_addr, 0, sizeof(_sock_addr) );
    _sock_addr.sin_addr.s_addr = _in_addr;
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(port);

    // Async Socket Connecting
    unsigned long _u = 1;
    CLEANDNS_NETWORK_IOCTL_CALL(m_socket, FIONBIO, &_u);

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
                CLEANDNS_NETWORK_CLOSESOCK( m_socket );
                return false;
            }
        } else {
            // Failed to connect
            CLEANDNS_NETWORK_CLOSESOCK( m_socket );
            return false;
        }
    }
    // Reset Socket Statue
    _u = 0;
    CLEANDNS_NETWORK_IOCTL_CALL(m_socket, FIONBIO, &_u);

    return true;
}
// Listen on specified port and address, default is 0.0.0.0
bool cleandns_tcpsocket::listen( u_int32_t port, u_int32_t ipaddr )
{
    struct sockaddr_in _sock_addr;
    m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;

    memset((char *)&_sock_addr, 0, sizeof(_sock_addr));
    _sock_addr.sin_family = AF_INET;
    _sock_addr.sin_port = htons(port);
    _sock_addr.sin_addr.s_addr = htonl(ipaddr);

    if ( bind(m_socket, (struct sockaddr *)&_sock_addr, sizeof(_sock_addr)) == -1 ) {
        CLEANDNS_NETWORK_CLOSESOCK( m_socket );
        return false;
    }
    if ( -1 == ::listen(m_socket, 100) ) {
        CLEANDNS_NETWORK_CLOSESOCK( m_socket );
        return false;
    }
    _svrfd = (struct pollfd *)calloc(1, sizeof(struct pollfd));
    _svrfd->events = POLLIN | POLLPRI;
    _svrfd->fd = m_socket;

    return true;
}
// Close the connection
void cleandns_tcpsocket::close()
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return;
    CLEANDNS_NETWORK_CLOSESOCK(m_socket);
    m_socket = INVALIDATE_SOCKET;
    if ( _svrfd != NULL ) {
        free( _svrfd );
        _svrfd = NULL;
    }
}
// When the socket is a listener, use this method 
// to accept client's connection.
cleandns_tcpsocket *cleandns_tcpsocket::get_client( u_int32_t timeout )
{
    if ( _svrfd == NULL ) return NULL;
    size_t _nfds = 1;   // number of fd
    int _ret = 0;
    _ret = poll( _svrfd, _nfds, timeout );
    if ( _ret == -1 ) {
        this->close();
        return NULL;
    }

    if ( _svrfd->revents == 0 ) {
        // No incoming socket
        return NULL;
    }
    if ( _svrfd->revents & POLLIN ) {
        // PINFO("New incoming socket.");
        struct sockaddr_in _sockInfoClient;
        int _len = 0;
        SOCKET_T _clt = accept(m_socket, (struct sockaddr *)&_sockInfoClient, (socklen_t *)&_len);

        // Accept and create new client socket.
        if ( _clt == -1 ) return NULL;
        cleandns_tcpsocket *_client_socket = new cleandns_tcpsocket;
        _client_socket->m_socket = _clt;
        _client_socket->set_reusable( );

        return _client_socket;
    }
    return NULL;
}

// Set current socket reusable or not
bool cleandns_tcpsocket::set_reusable( bool reusable )
{
    if ( m_socket == INVALIDATE_SOCKET ) return false;
    int _reused = reusable ? 1 : 0;
    return setsockopt( m_socket, SOL_SOCKET, SO_REUSEADDR,
        (const char *)&_reused, sizeof(int) ) != -1;
}

// Read data from the socket until timeout or get any data.
bool cleandns_tcpsocket::read_data( string &buffer, u_int32_t timeout )
{
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;

    buffer = "";
    struct timeval _tv = { (long)timeout / 1000, 
        static_cast<int>(((long)timeout % 1000) * 1000) };
    fd_set recvFs;
    FD_ZERO( &recvFs );
    FD_SET( m_socket, &recvFs );

    // Buffer
    char _buffer[512] = { 0 };
    int _idleLoopCount = 5;

    do {
        // Wait for the incoming
        int _retCode = 0;
        do {
            _retCode = ::select( m_socket + 1, &recvFs, NULL, NULL, &_tv );
        } while ( _retCode < 0 && errno == EINTR );

        if ( _retCode < 0 ) // Error
            return false;
        if ( _retCode == 0 )    // TimeOut
            return true;

        // Get data from the socket cache
        _retCode = ::recv( m_socket, _buffer, 512, 0 );
        // Error happen when read data, means the socket has become invalidate
        if ( _retCode < 0 ) return false;
        if ( _retCode == 0 ) break; // Get EOF
        buffer.append( _buffer, _retCode );

        do {
            // Check if the socket has more data to read
            SOCKETSTATUE _status = socket_check_status(m_socket, SO_CHECK_READ);
            // Socket become invalidate
            if (_status == SO_INVALIDATE) 
            {
                if ( buffer.size() > 0 ) return true;
                return false;
            }
            // Socket become idle, and already read some data, means the peer finish sending one
            // package. We return the buffer and make the up-level to process the package.
            //PDUMP(_idleLoopCount);
            if (_status == SO_IDLE) {
                //PDUMP( _idleLoopCount );
                if ( _idleLoopCount > 0 ) _idleLoopCount -= 1;
                else return true;
            } else break;
        } while ( _idleLoopCount > 0 );
    } while ( true );

    // Useless
    return true;
}
// Write data to peer.
bool cleandns_tcpsocket::write_data( const string &data )
{
    if ( data.size() == 0 ) return false;
    if ( SOCKET_NOT_VALIDATE(m_socket) ) return false;
    u_int32_t _write_timeout = 1000;

#if defined WIN32 || defined _WIN32 || defined WIN64 || defined _WIN64
    setsockopt( m_socket, SOL_SOCKET, SO_SNDTIMEO,
        (const char *)&_write_timeout, sizeof(Uint32) );
#else
    struct timeval wtv = { _write_timeout / 1000, 
        static_cast<int>((_write_timeout % 1000) * 1000) };
    setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, 
        (const char *)&wtv, sizeof(struct timeval));
#endif

    int _allSent = 0;
    int _lastSent = 0;

    u_int32_t _length = data.size();
    const char *_data = data.c_str();

    while ( (unsigned int)_allSent < _length )
    {
        _lastSent = ::send( m_socket, _data + _allSent, 
            (_length - (unsigned int)_allSent), 0 | CLEANDNS_NETWORK_NOSIGNAL );
        if( _lastSent < 0 ) {
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