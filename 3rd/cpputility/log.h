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

#ifndef __CPP_UTILITY_LOG_H__
#define __CPP_UTILITY_LOG_H__

#include <iostream>
#include <ctime>
#include <chrono>
#include <fstream>
#include <syslog.h>

using namespace std;
using namespace std::chrono;

namespace cpputility {
    typedef enum {
    	log_emergancy		= LOG_EMERG,	// 0
    	log_alert			= LOG_ALERT,	// 1
    	log_critical		= LOG_CRIT,		// 2
    	log_error			= LOG_ERR,		// 3
    	log_warning			= LOG_WARNING,	// 4
    	log_notice			= LOG_NOTICE,	// 5
    	log_info			= LOG_INFO,		// 6
    	log_debug			= LOG_DEBUG		// 7
    } cp_log_level;

    // Start & Stop log server
    // Log to file
    void cp_log_start(const string &logpath, cp_log_level lv);
    // Log to specified fp, like stderr, stdout
    void cp_log_start(FILE *fp, cp_log_level lv);
    // Log to syslog
    void cp_log_start(cp_log_level lv);

    // Stop the log thread
    void cp_log_stop();

    // Write the loc
    void cp_log(cp_log_level lv, const char *format, ...);    
}

#endif // tinydst.log.h

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
