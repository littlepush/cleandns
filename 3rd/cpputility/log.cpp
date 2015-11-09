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

#include "log.h"
#include "thread.h"
#include <cstdarg>

namespace cpputility {
	
	typedef pair<cp_log_level, string>	log_item_t;
	static cp_log_level g_loglv = log_info;
	static bool g_logsys = false;
	static string g_logpath;
	static FILE *g_logfp = NULL;
	static event_pool<log_item_t> g_logpool;
	static mutex g_logmutex;
	static bool g_logstatus = true;
	static thread *g_logthread = NULL;

	inline bool cp_log_status() {
		unique_lock<mutex> _l(g_logmutex);
		return g_logstatus;
	}

	inline const char *cp_log_lv_to_string(cp_log_level lv) {
		static const char *_lvname[8] = {
			"emergancy",
			"critical",
			"alert",
			"error",
			"warning",
			"notice",
			"info",
			"debug"
		};
		return _lvname[lv];
	}

	inline void cp_log_get_time(string & logline) {
		auto _now = system_clock::now();
		auto _time_t = system_clock::to_time_t(_now);
		auto _time_point = _now.time_since_epoch();
		_time_point -= duration_cast<seconds>(_time_point); 
		auto _tm = localtime(&_time_t);
		size_t _current_sz = logline.size();
		logline.resize(_current_sz + 25);	// '[yyyy-MM-dd hh:mm:ss.zzz]'

		sprintf(&logline[_current_sz], "[%04d-%02d-%02d %02d:%02d:%02d.%03d]", 
				_tm->tm_year + 1900, _tm->tm_mon + 1, _tm->tm_mday,
				_tm->tm_hour, _tm->tm_min, _tm->tm_sec,
				static_cast<unsigned>(_time_point / milliseconds(1)));
	}

	void cp_log_write_worker( ) {
		log_item_t _logitem;
		while ( cp_log_status() ) {
			if ( !g_logpool.wait_for(milliseconds(10), [&](log_item_t&& line){
						_logitem.swap(line);
					}) ) continue;
			if ( g_logfp != NULL ) {
				fprintf(g_logfp, "%s\n", _logitem.second.c_str());
			} else if ( g_logsys ) {
				// Syslog
				syslog(_logitem.first, "%s\n", _logitem.second.c_str());
			} else {
				// To file
				do {
					g_logfp = fopen(g_logpath.c_str(), "a+");
				} while ( g_logfp == NULL );
				fprintf(g_logfp, "%s\n", _logitem.second.c_str());
				fclose(g_logfp);
				g_logfp = NULL;
			}
		}
	}

	void cp_start_log_thread( ) {
		if ( g_logthread != NULL ) return;
		g_logstatus = true;
		g_logthread = new thread(cp_log_write_worker);
	}
	// Start & Stop log server
	// Log to file
	void cp_log_start(const string &logpath, cp_log_level lv) {
		g_logfp = NULL;
		g_logpath = logpath;
		g_loglv = lv;
		g_logsys = false;
		cp_start_log_thread();
	}
	// Log to specified fp, like stderr, stdout
	void cp_log_start(FILE *fp, cp_log_level lv) {
		g_logfp = fp;
		g_loglv = lv;
		g_logpath = "";
		g_logsys = false;
		cp_start_log_thread();
	}
	// Log to syslog
	void cp_log_start(cp_log_level lv) {
		setlogmask(LOG_UPTO(lv));
		openlog("tinydst", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

		g_logsys = true;
		g_loglv = lv;
		g_logfp = NULL;
		g_logpath = "";
		cp_start_log_thread();
	}

	// Stop the log thread
	void cp_log_stop() {
		do {
			//unique_lock<mutex> _l(g_logmutex);
			lock_guard<mutex> _l(g_logmutex);
			g_logstatus = false;
		} while ( false );
		g_logthread->join();
		delete g_logthread;
		g_logthread = NULL;

		// Close system log
		if ( g_logsys ) {
			closelog();
		}
		g_logsys = false;
	}

	// Write the loc
	void cp_log(cp_log_level lv, const char *format, ...) {
		// Check log level
		if ( lv > g_loglv ) return;

		string _logline;
		if ( g_logsys == false ) {
			cp_log_get_time(_logline);
			_logline += "[";
			_logline += cp_log_lv_to_string(lv);
			_logline += "] ";
		}

		va_list _va;
		va_start(_va, format);
		size_t _fmtsize = vsnprintf(NULL, 0, format, _va);
		va_end(_va);
		size_t _crtsize = _logline.size();
		_logline.resize(_crtsize + _fmtsize + 1);
		va_start(_va, format);
		vsnprintf(&_logline[_crtsize], _fmtsize + 1, format, _va);
		va_end(_va);

		g_logpool.notify_one(make_pair(lv, _logline));
	}
	
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
