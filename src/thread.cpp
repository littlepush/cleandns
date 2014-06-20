/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : thread.cpp
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

#include "thread.h"

cleandns_thread::cleandns_thread( thread_job_t job )
: m_thread_handler(-1), m_thread_id(0), m_thread_status(false), m_job(job)
{
    // Nothing to do...
    m_thread_sync_sem.initialize(0);
}
cleandns_thread::~cleandns_thread()
{
    this->stop_thread( );
}
// Status
bool cleandns_thread::thread_status()
{
    cleandns_lock _lock(m_running_mutex);
    return m_thread_status;
}

// Thread control
bool cleandns_thread::start_thread()
{
    if ( m_job == NULL ) return false;
    cleandns_lock _lock(m_running_mutex);
    if ( m_thread_status == true ) return false;
#if _DEF_WIN32
    m_thread_handler = ::_beginthreadex( 
        NULL, 0x40000, &cleandns_thread::_thread_main, 
        this, 0, (unsigned *)&m_thread_id);
    if ( m_thread_handler == 0 || m_thread_handler == -1 )
        return false;
#else
    pthread_attr_t _tAttr;
    int ret = pthread_attr_init( &_tAttr );
    if ( ret != 0 ) return false;
    ret = pthread_attr_setstacksize( &_tAttr, 0x40000 );
    if ( ret != 0 ) return false;
    m_thread_handler = pthread_create(&m_thread_id, 
        &_tAttr, &cleandns_thread::_thread_main, this);
    pthread_attr_destroy(&_tAttr);
    if ( m_thread_handler != 0 ) return false;
#endif
    return m_thread_sync_sem.get( );
}
bool cleandns_thread::stop_thread( bool wait_until_exit )
{
    if ( this->thread_status() == false ) return true;
    // Manually lock
    m_running_mutex.lock();
    m_thread_status = false;
    m_running_mutex.unlock();

    if ( wait_until_exit ) {
        m_thread_sync_sem.get( );
    }
    return true;
}

// Global thread callback function.
thread_return_t _THREAD_CALLBACK cleandns_thread::_thread_main( void *param )
{
    cleandns_thread *_pcd_thread = (cleandns_thread *)param;
    _pcd_thread->m_thread_status = true;
    _pcd_thread->m_thread_sync_sem.give();

    // Invoke the job
    _pcd_thread->m_job( _pcd_thread );

    // Stop the thread
    if ( _pcd_thread->m_thread_id == 0 ) return 0;
#if _DEF_WIN32
    ::CloseHandle((HANDLE)_pcd_thread->m_thread_handler);
    _pcd_thread->m_thread_handler = 0;
#endif

#if !_DEF_WIN32
    // Detach current thread's resource.
    pthread_detach( _pcd_thread->m_thread_id );
#endif
    _pcd_thread->m_thread_id = 0;
    _pcd_thread->m_thread_sync_sem.give();
    return 0;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */