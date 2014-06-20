/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : lock.h
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

#ifndef __CLEAN_DNS_LOCK_H__
#define __CLEAN_DNS_LOCK_H__

#include "config.h"

class cleandns_mutex;
class cleandns_semaphore;

#if _DEF_WIN32
        typedef ::CRITICAL_SECTION  cleandns_mutex_t;
#else
        typedef pthread_mutex_t     cleandns_mutex_t;
#endif

// Mutex
class cleandns_mutex
{
protected:
    friend class cleandns_semaphore;
    cleandns_mutex_t m_mutex;
public:
    cleandns_mutex();
    ~cleandns_mutex();

    void lock();
    void unlock();
    bool trylock();
};

// Auto locker
class cleandns_lock
{
    cleandns_mutex &_lock;
public:
    cleandns_lock( cleandns_mutex & l );
    ~cleandns_lock();
};

#if _DEF_WIN32
    typedef void *          cleandns_sem_t;
#else
    typedef pthread_cond_t  cleandns_sem_t;
#endif

// Semaphore
class cleandns_semaphore
{
public:
    enum { MAXCOUNT = 0x0FFFF, MAXTIMEOUT = 0xFFFFFFFF };
protected:
    cleandns_sem_t m_sem;
    Int32 m_max;
    volatile Int32 m_current;
    volatile bool m_available;

    // Mutex for the semaphore
    cleandns_mutex m_mutex;

    #if !(_DEF_WIN32)
        // Cond Mutex.
        pthread_condattr_t m_cond_attr;
    #endif

public:
    cleandns_semaphore();
    cleandns_semaphore( unsigned int init, unsigned int max = MAXCOUNT );
    ~cleandns_semaphore();

    // Get current count
    Uint32 count();

    // Try to get a signal, and wait until timeout
    // If timeout is equal to MAXTIMEOUT, will not return unless did get a signal.
    bool get( Uint32 timeout = MAXTIMEOUT );

    // Release or give a signal to the pool.
    bool give();

    // Manually initialize the semaphore
    void initialize( unsigned int init, unsigned int max = MAXCOUNT );

    // Manually destory the semaphore
    void destory();

    // Tell if current semaphore is still available
    bool is_available();

protected:
    void _try_set_statue( bool statue );
};

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */