/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : thread.h
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

#ifndef __CLEAN_DNS_THREAD_H__
#define __CLEAN_DNS_THREAD_H__

#include "config.h"
#include "lock.h"

#if _DEF_WIN32
typedef long        thread_handle;
typedef long        thread_id_t;
typedef Uint32      thread_return_t;

#define _THREAD_CALLBACK    __stdcall
#else
typedef int         thread_handle;
typedef pthread_t   thread_id_t;
typedef void *      thread_return_t;

#define _THREAD_CALLBACK
#endif

class cleandns_thread;
typedef void (*thread_job_t)( cleandns_thread *thread );

// Thread Utility (Lite Version)
class cleandns_thread
{
protected:
    thread_handle           m_thread_handler;
    thread_id_t             m_thread_id;
    volatile bool           m_thread_status;
    cleandns_mutex          m_running_mutex;
    cleandns_semaphore      m_thread_sync_sem;

    thread_job_t            m_job;
public:

    // Create a thread with job function
    cleandns_thread( thread_job_t job );
    ~cleandns_thread();

    // Status
    bool thread_status();

    // Thread control
    bool start_thread();
    bool stop_thread( bool wait_until_exit = true );

protected:

    // Global thread callback function.
    static thread_return_t _THREAD_CALLBACK _thread_main( void *param );
};

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */