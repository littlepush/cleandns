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
#include "cf.h"
#include <fstream>

// Default redirect rule
redirect_rule *_default_rule;
vector<redirect_rule *> _rules;

unsigned int _server_port = 53;

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
        bool _status = false;
        for ( int i = 0; i < _rules.size(); ++i ) {
            if ( !_rules[i]->redirect_query(_client_socket, _domain, _client_socket->m_data) ) continue;
            _status = true; 
            break;
        }

        if ( !_status ) {
            _default_rule->redirect_query(_client_socket, _domain, _client_socket->m_data );
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
    int _time = 1;
    bool _st = false;
    for ( int i = 0; i < 6; ++i ) {
        if ( !_udp_svr_so.listen(53) ) {
            cerr << "cleandns: failed to listen on 53 for udp worker." << endl;
            sleep( _time *= 2 );
        }
        _st = true;
        break;
    }
    if ( _st == false ) {
        cerr << "cleandns: failed to listen on 53 for udp worker, exit." << endl;
        exit(1);
    }
    while( (*thread)->thread_status() ) {
        cleandns_udpsocket *_client = _udp_svr_so.get_client();
        if ( _client == NULL ) continue;
        cleandns_thread *_redirect_thread = new cleandns_thread(cleandns_udp_client_redirector);
        _redirect_thread->user_info = _client;
        _redirect_thread->start_thread();
    }
}

void cleandns_tcp_client_redirector( cleandns_thread **thread )
{
    cleandns_tcpsocket *_client_socket = (cleandns_tcpsocket *)(*thread)->user_info;
    if ( _client_socket == NULL ) {
        delete (*thread);
        *thread = NULL;
        return;
    }

    do {
        string _buffer;
        if ( !_client_socket->read_data( _buffer, 3000 ) ) break;
        string _domain;
        int _ret = dns_get_domain(_buffer.c_str(), _buffer.size(), _domain);
        if ( _ret != 0 ) {
            cerr << "cleandns: failed to get domain info from the package.";
            break;
        }
        bool _status = false;
        for ( int i = 0; i < _rules.size(); ++i ) {
            if ( !_rules[i]->redirect_query(_client_socket, _domain, _buffer) ) continue;
            _status = true; 
            break;
        }

        if ( !_status ) {
            _default_rule->redirect_query(_client_socket, _domain, _buffer );
        }
    } while ( false );

    delete _client_socket;
    delete (*thread);
    *thread = NULL;
}
void cleandns_tcp_client_worker( cleandns_thread **thread )
{
    cleandns_tcpsocket _tcp_svr_so;
    int _time = 1;
    bool _st = false;
    for ( int i = 0; i < 6; ++i ) {
        if ( !_tcp_svr_so.listen(53) ) {
            cerr << "cleandns: failed to listen on 53 for tcp worker." << endl;
            sleep( _time *= 2 );
        }
        _st = true;
        break;
    }
    if ( _st == false ) {
        cerr << "cleandns: failed to listen on 53 for tcp worker, exit." << endl;
        exit(1);
    }
    while( (*thread)->thread_status() ) {
        cleandns_tcpsocket *_client = _tcp_svr_so.get_client();
        if ( _client == NULL ) continue;
        cleandns_thread *_redirect_thread = new cleandns_thread(cleandns_tcp_client_redirector);
        _redirect_thread->user_info = _client;
        _redirect_thread->start_thread();
    }
}

void cleandns_tcp_server_redirector( cleandns_thread **thread )
{
    cleandns_tcpsocket *_client_socket = (cleandns_tcpsocket *)(*thread)->user_info;
    if ( _client_socket == NULL ) {
        delete (*thread);
        *thread = NULL;
        return;
    }

    do {
        string _buffer;
        if ( !_client_socket->read_data( _buffer, 3000 ) ) break;
        bool _status = false;
        for ( int i = 0; i < _rules.size(); ++i ) {
            if ( !_rules[i]->redirect_udp_query(_client_socket, _buffer) ) continue;
            _status = true; 
            break;
        }

        if ( !_status ) {
            _default_rule->redirect_udp_query(_client_socket, _buffer );
        }
    } while ( false );

    delete _client_socket;
    delete (*thread);
    *thread = NULL;
}
void cleandns_tcp_server_worker( cleandns_thread **thread )
{
    cleandns_tcpsocket _tcp_svr_so;
    if ( !_tcp_svr_so.listen(_server_port) ) {
        cerr << "cleandns: failed to listen on " << _server_port << "." << endl;
        exit(3);
    }
    while( (*thread)->thread_status() ) {
        cleandns_tcpsocket *_client = _tcp_svr_so.get_client();
        if ( _client == NULL ) continue;
        cleandns_thread *_redirect_thread = new cleandns_thread(cleandns_tcp_server_redirector);
        _redirect_thread->user_info = _client;
        _redirect_thread->start_thread();
    }
}

void _cleandns_version_info() {
    printf( "cleandns version: %s\n", VERSION );
    printf( "target: %s\n", TARGET );
    printf( "Visit <https://github.com/littlepush/cleandns> for more infomation.\n" );
}

void _cleandns_help_info() {
    _cleandns_version_info();
    printf( "cleandns --config <file>\n");
    printf( "options: \n" );
    printf( "    --config|-c        The configuration file path\n" );
}

int main( int argc, char *argv[] ) {
    const char *_home_path = getenv("HOME");
    string _config_file = string(_home_path) + "/.cleandns.conf";

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
            if ( _command == "-c" || _command == "--config" ) {
                if ( _arg + 1 < argc ) {
                    _config_file = argv[++_arg];
                } else {
                    cerr << "Invalidate argument: " << _command << ", missing parameter." << endl;
                    return 1;
                }
                continue;
            }
            cerr << "Invalidate argument: " << _command << "." << endl;
            return 1;
        }
    }

    config_section *_config = open_config_file(_config_file.c_str());
    if ( _config == NULL ) {
        cerr << "failed to open config file or invalidate configuration." << endl;
        return 1;
    }

    bool _is_client = false;
    bool _is_server = false;

    // Check work-mode
    if ( _config->contains_key("work-mode") ) {
        string _mode = (*_config)["work-mode"];
        if ( _mode == "client" ) {
            _is_client = true;
        } else if ( _mode == "server" ) {
            _is_server = true;
        } else {
            cerr << "error work-mode." << endl;
            close_config_file(_config);
            return 1;
        }
    } else {
        _is_client = true;
    }
    // Check rules
    config_section *_redirect_rules = _config->sub_section("redirect-rule");
    if ( _redirect_rules == NULL ) {
        cerr << "error, no redirect rule." << endl;
        close_config_file(_config);
        return 2;
    }

    pid_t _pid = fork();
    if ( _pid < 0 ) {
        cerr << "Failed to create child process." << endl;
        close_config_file(_config);
        return 2;
    }
    if ( _pid > 0 ) {
        // Has create the child process.
        close_config_file(_config);
        return 0;
    }

    if ( setsid() < 0 ) {
        cerr << "failed to set session leader for child process." << endl;
        close_config_file(_config);
        return 3;
    }

    set_signal_handler();
    cleandns_thread *_client_udp_worker_thread = NULL;
    cleandns_thread *_client_tcp_worker_thread = NULL;
    cleandns_thread *_server_tcp_worker_thread = NULL;

    // Load configuration
    vector< string > _rule_name_list;
    _redirect_rules->get_sub_section_names(_rule_name_list);
    for ( int i = 0; i < _rule_name_list.size(); ++i ) {
        redirect_rule *_rule = new redirect_rule(_redirect_rules->sub_section(_rule_name_list[i]));
        if ( _rule->rule_name == "default" ) {
            _default_rule = _rule;
        } else {
            _rules.push_back(_rule);
        }
    }

    if ( _is_client ) {
        //cleandns_udp_client_worker
        _client_udp_worker_thread = new cleandns_thread( cleandns_udp_client_worker );
        _client_udp_worker_thread->start_thread();

        _client_tcp_worker_thread = new cleandns_thread( cleandns_tcp_client_worker );
        _client_tcp_worker_thread->start_thread();
    } else {
        // port
        if ( _config->contains_key("port") ) {
            _server_port = atoi((*_config)["port"].c_str());
        }
        _server_tcp_worker_thread = new cleandns_thread( cleandns_tcp_server_worker );
        _server_tcp_worker_thread->start_thread();
    }

    // Done
    close_config_file(_config);

    // Wait for close signal and exit
    wait_for_exit_signal();
    if ( _is_client ) {
        if ( _client_udp_worker_thread ) _client_udp_worker_thread->stop_thread();
        if ( _client_tcp_worker_thread ) _client_tcp_worker_thread->stop_thread();
    } else {
        if ( _server_tcp_worker_thread ) _server_tcp_worker_thread->stop_thread();
    }

    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
