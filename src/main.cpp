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

void _cleandns_version_info() {
    printf( "cleandns version: %s\n", VERSION );
    printf( "target: %s\n", TARGET );
    printf( "Visit <https://github.com/littlepush/cleandns> for more infomation.\n" );
}

void _cleandns_help_info() {
    _cleandns_version_info();
    printf( "cleandns --client --filter <file> --server <server> --port <port> --local <dns>\n");
    printf( "cleandns --server --port <port> --local <dns>\n");
    printf( "options: \n" );
    printf( "    --filter|-f        The filter file path\n" );
    printf( "    --server|-s        Server side address for proxy\n" );
    printf( "    --port|-p          Server side port for proxy\n" );
    printf( "    --local|-l         Local parent dns address\n" );
}

int main( int argc, char *argv[] ) {
    const char *_home_path = getenv("HOME");
    string _filter_list_file = string(_home_path) + "/.cleandns.filter";
    string _server_address = "127.0.0.1";
    unsigned int _server_port = 11025;
    string _local_address = "202.96.209.133";
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
            if ( _command == "-s" || _command == "--server" ) {
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
                _is_server == true;
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

    cout << "Filter File: " << _filter_list_file << endl;
    cout << "Server Port: " << _server_port << endl;
    cout << "Server Address: " << _server_address << endl;
    cout << "Local Address: " << _local_address << endl;
    cout << "Is Client: " << _is_client << endl;
    cout << "is Server: " << _is_server << endl;

    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */