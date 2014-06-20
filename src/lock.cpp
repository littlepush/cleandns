/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : lock.cpp
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
#include "lock.h"

cleandns_mutex::cleandns_mutex()
{
#if _DEF_WIN32
    #if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0403)
        // for better performance.
        ::InitializeCriticalSectionAndSpinCount( &m_mutex, 4000 );
    #else
        ::InitializeCriticalSection( &m_mutex );
    #endif
#else
    pthread_mutex_init(&m_mutex, NULL);
#endif
}
cleandns_mutex::~cleandns_mutex()
{
#if defined WIN32 || defined _WIN32
    ::DeleteCriticalSection( &m_mutex );
#else
    pthread_mutex_destroy(&m_mutex);
#endif
}

void cleandns_mutex::lock()
{
#if _DEF_WIN32
    ::EnterCriticalSection( &m_mutex );
#else 
    pthread_mutex_lock(&m_mutex);
#endif
}
void cleandns_mutex::unlock()
{
#if _DEF_WIN32
    ::LeaveCriticalSection( &m_mutex );
#else
    pthread_mutex_unlock(&m_mutex);
#endif
}
bool cleandns_mutex::trylock()
{
#if _DEF_WIN32
    #if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0400)
        return ::TryEnterCriticalSection( &m_mutex ) != 0;
    #else
        return false;
    #endif
#else
    return pthread_mutex_trylock(&m_mutex) != 0;
#endif
}

// Clean dns Lock
cleandns_lock::cleandns_lock( cleandns_mutex & l ) : _lock( l )
{
    _lock.lock();
}
cleandns_lock::~cleandns_lock()
{
    _lock.unlock();
}

cleandns_semaphore::cleandns_semaphore()
: m_max(0), m_current(0), m_available(false)
{

}
cleandns_semaphore::cleandns_semaphore( unsigned int init, unsigned int max )
: m_max(0), m_current(0), m_available(false)
{
    this->initialize( init, max );
}
cleandns_semaphore::~cleandns_semaphore()
{
    this->destory();
}

// Get current count
Uint32 cleandns_semaphore::count()
{
    cleandns_lock _lock( m_mutex );
    return m_current;
}

// Try to get a signal, and wait until timeout
// If timeout is equal to MAXTIMEOUT, will not return unless did get a signal.
bool cleandns_semaphore::get( Uint32 timeout )
{
    if ( !this->is_available() ) return false;
#if defined WIN32 || defined _WIN32
    if (::WaitForSingleObject(m_sem, timeout) != 0 ) return false;
#else
    cleandns_lock _lock( m_mutex );
    if ( m_current > 0 ) 
    {
        --m_current;
        return true;
    }
    int err;
    if ( timeout == MAXTIMEOUT ) {
        while( m_current == 0 ) 
        {
            if (pthread_cond_wait(&m_sem, &m_mutex.m_mutex) == EINVAL) {
                return false;
            }
        }
        m_current -= 1;
        return true;
    }
    else {
        struct timespec ts;
        struct timeval  tv;

        gettimeofday( &tv, NULL );
        ts.tv_nsec = tv.tv_usec * 1000 + ( timeout % 1000 ) * 1000000;
        int _OP = (ts.tv_nsec / 1000000000);
        if ( _OP ) ts.tv_nsec %= 1000000000;
        ts.tv_sec = tv.tv_sec + timeout / 1000 + _OP; 
        while( m_current == 0 )
        {
            err = pthread_cond_timedwait(&m_sem, &m_mutex.m_mutex, &ts);
            // On Time Out or Invalidate Object.
            if ( err == ETIMEDOUT || err == EINVAL ) {
                return false;
            }
        }
        m_current -= 1;
        return true;
    }
#endif  
#if _DEF_WIN32
    cleandns_lock _lock( m_mutex );
    ::InterlockedDecrement((LONG *)&m_current);
    return (m_current >= 0);
#endif
}

// Release or give a signal to the pool.
bool cleandns_semaphore::give()
{
    if ( !this->is_available() ) return false;
    cleandns_lock _lock(m_mutex);
    if ( m_current == this->m_max ) {
        return false;
    }
#if _DEF_WIN32
    ::InterlockedIncrement((LONG *)&m_current);
    ::ReleaseSemaphore(m_sem, 1, NULL);
#else
    ++m_current;
    pthread_cond_signal(&m_sem);
#endif
    return true;
}

// Manually initialize the semaphore
void cleandns_semaphore::initialize( unsigned int init, unsigned int max )
{
    this->destory();
#if _DEF_WIN32
    m_sem = ::CreateSemaphore(NULL, init, max, NULL);
#else
    pthread_condattr_init(&m_cond_attr);
    pthread_cond_init(&m_sem, &m_cond_attr);
#endif
    this->m_current = init;
    this->m_max = max;
    this->_try_set_statue( true );
}

// Manually destory the semaphore
void cleandns_semaphore::destory()
{
    if ( !this->is_available() ) return;
#if _DEF_WIN32
    ::CloseHandle(m_sem);
#else
    //sem_destroy(&m_Sem);
    pthread_condattr_destroy(&m_cond_attr);
    pthread_cond_destroy(&m_sem);
#endif
    this->_try_set_statue(false);
    this->m_current = 0;
}

// Tell if current semaphore is still available
bool cleandns_semaphore::is_available()
{
    cleandns_lock _lock(m_mutex);
    return m_available;
}

void cleandns_semaphore::_try_set_statue( bool statue )
{
    cleandns_lock _lock( m_mutex );
    if ( m_available == statue ) return;
    m_available = statue;
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */