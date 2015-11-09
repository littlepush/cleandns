/*
    CppUtility -- a C++ Utility Library for Linux/Windows/iOS
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

#include "thread.h"
#include <map>

namespace cpputility {
    static mutex& __g_mutex() {
        static mutex _m;
        return _m;
    }
    static void __h_signal( int sig ) {
        if ( SIGTERM == sig || SIGINT == sig || SIGQUIT == sig ) {
            __g_mutex().unlock();
        }
    }
    void set_signal_handler() {
        __g_mutex().lock();
    #if SL_TARGET_MAC
        signal(SIGINT, __h_signal); 
    #elif SL_TARGET_LINUX
        sigset_t sgset, osgset;
        sigfillset(&sgset);
        sigdelset(&sgset, SIGTERM); 
        sigdelset(&sgset, SIGINT);
        sigdelset(&sgset, SIGQUIT);
        sigdelset(&sgset, 11);
        sigprocmask(SIG_SETMASK, &sgset, &osgset);
        signal(SIGTERM, __h_signal);
        signal(SIGINT, __h_signal);
        signal(SIGQUIT, __h_signal);
    #endif
    }

    void wait_for_exit_signal() {
        __g_mutex().lock();
        __g_mutex().unlock();
    }

    static map< thread::id, pair< shared_ptr<mutex>, shared_ptr<bool> > >& __g_threadinfo() {
        static map< thread::id, pair< shared_ptr<mutex>, shared_ptr<bool> > > _m;
        return _m;
    }
    void register_this_thread() {
        __g_threadinfo()[this_thread::get_id()] = make_pair(make_shared<mutex>(), make_shared<bool>(true));
    }
    void join_all_threads() {
        for ( auto &_kv : __g_threadinfo() ) {
            lock_guard<mutex>(*_kv.second.first);
            *_kv.second.second = false;
        }
    }
    bool this_thread_is_running() {
        auto _it = __g_threadinfo().find(this_thread::get_id());
        if ( _it == end(__g_threadinfo()) ) return false;
        lock_guard<mutex>(*_it->second.first);
        return *_it->second.second;
    }
}

// tinydst.thread.cpp

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
