/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : main.cpp
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

#include "config.h"
#include "dns.h"
#include "lock.h"
#include "thread.h"
#include "tcpsocket.h"
#include "udpsocket.h"
#include <fstream>

// Global Parameters
string _server_address = "127.0.0.1";
unsigned int _server_port = 11025;
string _local_address = "202.96.209.133";

#if _DEF_WIN32
void set_signal_handler( ) {
}
void wait_for_exit_signal( )
{
    char _c = getc( );
}
#else
// Global Signal
struct __global_signal {
    static cleandns_semaphore & __wait_sem( ) {
        static cleandns_semaphore _sem(0, 1);
        return _sem;
    }
};

void __handle_signal( int _sig ) {
    if (SIGTERM == _sig || SIGINT == _sig || SIGQUIT == _sig) {
        __global_signal::__wait_sem().give();          
    }
}
void set_signal_handler( ) {
    // Hook the signal
#ifdef __APPLE__
    signal(SIGINT, __handle_signal);
#else
    sigset_t sgset, osgset;
    sigfillset(&sgset);
    sigdelset(&sgset, SIGTERM);
    sigdelset(&sgset, SIGINT);
    sigdelset(&sgset, SIGQUIT);
    sigdelset(&sgset, 11);
    sigprocmask(SIG_SETMASK, &sgset, &osgset);
    signal(SIGTERM, __handle_signal);
    signal(SIGINT, __handle_signal);
    signal(SIGQUIT, __handle_signal);    
#endif      
}
void wait_for_exit_signal( )
{
    // Wait for exit signal
    __global_signal::__wait_sem().get( );     
}
#endif

void cleandns_udp_client_redirector( cleandns_thread **thread )
{
    cleandns_udpsocket *_client_socket = (cleandns_udpsocket *)(*thread)->user_info;
    if ( _client_socket == NULL ) {
        delete (*thread);
        *thread = NULL;
        return;
    }

    do {
        string _domain;
        int _ret = dns_get_domain(_client_socket->m_data.c_str(), _client_socket->m_data.size(), _domain);
        if ( _ret != 0 ) {
            cerr << "cleandns: failed to get domain info from the package.";
            break;
        }
        bool _is_filter_domain = domain_match_filter( _domain );
        if ( _is_filter_domain ) {
            cleandns_tcpsocket _re_socket;
            if ( !_re_socket.connect( _server_address, _server_port) ) break;
            if ( !_re_socket.write_data(_client_socket->m_data) ) break;
            if ( !_re_socket.read_data(_client_socket->m_data, 5000) ) break;
            _re_socket.close();

            _client_socket->write_data(_client_socket->m_data);
        } else {
            // Redirect to local server use udp
            cleandns_udpsocket _re_socket;
            if ( !_re_socket.connect( _local_address, 53 ) ) break;
            if ( !_re_socket.write_data(_client_socket->m_data) ) break;
            if ( !_re_socket.read_data(_client_socket->m_data, 3000) ) break;
            _re_socket.close();

            _client_socket->write_data(_client_socket->m_data);
        }
    } while ( false );

    // Release result
    delete _client_socket;
    delete (*thread);
    *thread = NULL;
}

void cleandns_udp_client_worker( cleandns_thread **thread )
{
    cleandns_udpsocket _udp_svr_so;
    if ( !_udp_svr_so.listen(53) ) {
        sleep(1);
        cerr << "cleandns: failed to listen on 53 for udp worker." << endl;
        exit(2);
    }
    while( (*thread)->thread_status() ) {
        cleandns_udpsocket *_client = _udp_svr_so.get_client();
        if ( _client == NULL ) continue;
        cleandns_thread *_redirect_thread = new cleandns_thread(cleandns_udp_client_redirector);
        _redirect_thread->user_info = _client;
        _redirect_thread->start_thread();
    }
}

void cleandns_tcp_client_worker( cleandns_thread **thread )
{
    cleandns_tcpsocket _tcp_svr_so;
    if ( !_tcp_svr_so.listen(53) ) {
        cerr << "cleandns: failed to listen on 53 for tcp worker." << endl;
        exit(1);
    }
    while( (*thread)->thread_status() ) {
        cleandns_tcpsocket *_client = _tcp_svr_so.get_client();
        if ( _client == NULL ) continue;
        string _buffer;
        _client->read_data(_buffer);
        cout << _buffer << endl;
        delete _client;
    }
}

void cleandns_tcp_server_worker( cleandns_thread **thread )
{
    while( (*thread)->thread_status() ) {
        sleep( 1 );
        cout << "server tcp worker running" << endl;
    }
}

void _cleandns_version_info() {
    printf( "cleandns version: %s\n", VERSION );
    printf( "target: %s\n", TARGET );
    printf( "Visit <https://github.com/littlepush/cleandns> for more infomation.\n" );
}

void _cleandns_help_info() {
    _cleandns_version_info();
    printf( "cleandns --client --filter <file> --remote <remote> --port <port> --local <dns>\n");
    printf( "cleandns --server --port <port> --local <dns>\n");
    printf( "options: \n" );
    printf( "    --filter|-f        The filter file path\n" );
    printf( "    --remote|-r        Remote side address for proxy\n" );
    printf( "    --port|-p          Server side port for proxy\n" );
    printf( "    --local|-l         Local parent dns address\n" );
}

int main( int argc, char *argv[] ) {
    const char *_home_path = getenv("HOME");
    string _filter_list_file = string(_home_path) + "/.cleandns.filter";
    bool _is_client = false;
    bool _is_server = false;

    if ( argc >= 2 ) {
        int _arg = 1;
        for ( ; _arg < argc; ++_arg ) {
            string _command = argv[_arg];
            if ( _command == "-h" || _command == "--help" ) {
                // Help
                _cleandns_help_info();
                return 0;
            }
            if ( _command == "-v" || _command == "--version" ) {
                // Version
                _cleandns_version_info();
                return 0;
            }
            if ( _command == "-f" || _command == "--filter" ) {
                if ( _arg + 1 < argc ) {
                    _filter_list_file = argv[++_arg];
                } else {
                    cerr << "Invalidate argument: " << _command << ", missing parameter." << endl;
                    return 1;
                }
                continue;
            }
            if ( _command == "-l" || _command == "--local" ) {
                if ( _arg + 1 < argc ) {
                    _local_address = argv[++_arg];
                } else {
                    cerr << "Invalidate argument: " << _command << ", missing parameter." << endl;
                    return 1;
                }
                continue;
            }
            if ( _command == "-r" || _command == "--remote" ) {
                if ( _arg + 1 < argc ) {
                    _server_address = argv[++_arg];
                } else {
                    cerr << "Invalidate argument: " << _command << ", missing parameter." << endl;
                    return 1;
                }
                continue;
            }
            if ( _command == "-p" || _command == "--port" ) {
                if ( _arg + 1 < argc ) {
                    string _port = argv[++_arg];
                    _server_port = atoi(_port.c_str());
                    if ( _server_port == 0 || _server_port > 65535 ) {
                        cerr << "Invalidate port: " << _server_port << "." << endl;
                        return 1;
                    } 
                } else {
                    cerr << "Invalidate argument: " << _command << ", missing parameter." << endl;
                    return 1;
                }
                continue;
            }
            if ( _command == "--client" ) {
                _is_client = true;
                continue;
            }
            if ( _command == "--server" ) {
                _is_server = true;
            }
            cerr << "Invalidate argument: " << _command << "." << endl;
            return 1;
        }
    }

    if ( _is_client && _is_server ) {
        cerr << "Cannot be server and client at same time." << endl;
        return 1;
    }
    if ( !(_is_client || _is_server) ) {
        cerr << "Must specified to be client or server." << endl;
        return 1;
    }

    pid_t _pid = fork();
    if ( _pid < 0 ) {
        cerr << "Failed to create child process." << endl;
        return 2;
    }
    if ( _pid > 0 ) {
        // Has create the child process.
        return 0;
    }

    if ( setsid() < 0 ) {
        cerr << "failed to set session leader for child process." << endl;
        return 3;
    }

    set_signal_handler();
    cleandns_thread *_client_udp_worker_thread = NULL;
    cleandns_thread *_client_tcp_worker_thread = NULL;
    cleandns_thread *_server_tcp_worker_thread = NULL;

    if ( _is_client ) {
        // Try to read each line in the filter list.
        ifstream _filter_stream;
        _filter_stream.open(_filter_list_file.c_str(), ios_base::in);
        if ( _filter_stream ) {
            string _pattern_line;
            while ( _filter_stream.eof() == false ) {
                getline( _filter_stream, _pattern_line );
                _pattern_line = trim(_pattern_line);
                if ( _pattern_line.size() == 0 ) continue;
                dns_add_filter_pattern( _pattern_line );
            }
            _filter_stream.close();
        }

        //cleandns_udp_client_worker
        _client_udp_worker_thread = new cleandns_thread( cleandns_udp_client_worker );
        _client_udp_worker_thread->start_thread();

        _client_tcp_worker_thread = new cleandns_thread( cleandns_tcp_client_worker );
        _client_tcp_worker_thread->start_thread();
    } else {

    }

    // Wait for close signal and exit
    wait_for_exit_signal();
    if ( _is_client ) {
        if ( _client_udp_worker_thread ) _client_udp_worker_thread->stop_thread();
        if ( _client_tcp_worker_thread ) _client_tcp_worker_thread->stop_thread();
    } else {
        if ( _server_tcp_worker_thread ) _server_tcp_worker_thread->stop_thread();
    }

    exit(0);

    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
