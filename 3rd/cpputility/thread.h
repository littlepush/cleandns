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

#pragma once

#ifndef __CPP_UTILITY_THREAD_H__
#define __CPP_UTILITY_THREAD_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <csignal>

using namespace std;

namespace cpputility {

    // Hang up current process, and wait for exit signal
    void set_signal_handler();

    // Wait until we receive exit signal, this function will block
    // current thread.
    void wait_for_exit_signal();

    // Register current thread
    void register_this_thread();

    // Stop all thread registered
    void join_all_threads();

    // Check this thread's status
    bool this_thread_is_running();

    template < class Item > class event_pool
    {
    public:
    	typedef function<void(Item&&)>	get_event_t;
    protected:
    	mutex					mutex_;
    	condition_variable		cv_;
    	queue<Item>				pool_;

    public:

    	bool wait( get_event_t get_event ) {
    		unique_lock<mutex> _l(mutex_);
    		cv_.wait(_l, [this](){ return pool_.size() > 0; });
    		get_event(move(pool_.front()));
    		pool_.pop();
    		return true;
    	}

    	template< class Rep, class Period >
    	bool wait_for(const chrono::duration<Rep, Period>& rel_time, get_event_t get_event) {
    		unique_lock<mutex> _l(mutex_);
    		bool _result = cv_.wait_for(_l, rel_time, [this](){ return pool_.size() > 0; });
    		if ( _result == true ) {
    			get_event(move(pool_.front()));
    			pool_.pop();
    		}
    		return _result;
    	}

    	template< class Clock, class Duration >
    	bool wait_until(const chrono::time_point<Clock, Duration>& timeout_time, get_event_t get_event) {
    		unique_lock<mutex> _l(mutex_);
    		bool _result = cv_.wait_until(_l, timeout_time, [this](){ return pool_.size() > 0; });
    		if ( _result == true ) {
    			get_event(move(pool_.front()));
    			pool_.pop();
    		}
    		return _result;
    	}

    	void notify_one(Item&& item) {
    		unique_lock<mutex> _l(mutex_);
    		pool_.emplace(item);
    		cv_.notify_one();
    	};

    	void clear() {
    		lock_guard<mutex> _l(mutex_);
    		pool_.clear();
    	}
    };
}

#endif

// tinydst.thread.h

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
