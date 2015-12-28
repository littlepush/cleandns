/*
    socklite -- a C++ socket library for Linux/Windows/iOS
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
// This is an amalgamate file for socketlite

// Current Version: 0.6-rc5-6-geff30d5

#pragma once
// inc/thread.hpp
#ifndef __CPP_UTILITY_THREAD_H__
#define __CPP_UTILITY_THREAD_H__
    
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <csignal>
#include <map>
#include <iostream>
#include <unistd.h>

using namespace std;

namespace cpputility {

    // Internal Mutex
    inline mutex& __g_thread_mutex() {
        static mutex _m;
        return _m;
    }

    inline void __h_thread_signal( int sig ) {
        if ( SIGTERM == sig || SIGINT == sig || SIGQUIT == sig ) {
            __g_thread_mutex().unlock();
        }
    }

    // Hang up current process, and wait for exit signal
    inline void set_signal_handler() {
    #ifdef __APPLE__
        signal(SIGINT, __h_thread_signal);
        signal(SIGINT, __h_thread_signal);
        signal(SIGQUIT, __h_thread_signal);
    #elif ( defined WIN32 | defined _WIN32 | defined WIN64 | defined _WIN64 )
        // nothing
    #else
        sigset_t sgset, osgset;
        sigfillset(&sgset);
        sigdelset(&sgset, SIGTERM); 
        sigdelset(&sgset, SIGINT);
        sigdelset(&sgset, SIGQUIT);
        sigdelset(&sgset, 11);
        sigprocmask(SIG_SETMASK, &sgset, &osgset);
        signal(SIGTERM, __h_thread_signal);
        signal(SIGINT, __h_thread_signal);
        signal(SIGQUIT, __h_thread_signal);
    #endif
        __g_thread_mutex().lock();
    }

    // Wait until we receive exit signal, this function will block
    // current thread.
    inline void wait_for_exit_signal() {
        __g_thread_mutex().lock();
        __g_thread_mutex().unlock();
    }

    inline void send_exit_signal() {
        kill(getpid(), SIGQUIT);
    }

    class thread_info
    {
        typedef map< thread::id, pair< shared_ptr<mutex>, shared_ptr<bool> > > info_map_t;
    private:
        mutex               info_mutex_;
        info_map_t          info_map_;
    public:

        static thread_info& instance() {
            static thread_info _ti;
            return _ti;
        }

        // Register current thread
        void register_this_thread() {
            lock_guard<mutex> _(info_mutex_);
            info_map_[this_thread::get_id()] = make_pair(make_shared<mutex>(), make_shared<bool>(true));
        }
        // Unregister current thread and release the resource
        // then can join the thread.
        void unregister_this_thread() {
            lock_guard<mutex> _(info_mutex_);
            info_map_.erase(this_thread::get_id());
        }
        // Stop all thread registered
        void join_all_threads() {
            do {
                lock_guard<mutex> _(info_mutex_);
                for ( auto &_kv : info_map_ ) {
                    lock_guard<mutex>(*_kv.second.first);
                    *_kv.second.second = false;
                }
            } while( false );
            do {
                if ( true ) {
                    lock_guard<mutex> _(info_mutex_);
                    if ( info_map_.size() == 0 ) return;
                }
                //usleep(1000);   // wait for 1ms
                usleep(50);
            } while ( true );
        }
        // join specified thread
        void safe_join_thread(thread::id tid) {
            lock_guard<mutex> _(info_mutex_);
            auto _it = info_map_.find(tid);
            if ( _it == end(info_map_) ) {
                return;
            }
            lock_guard<mutex>(*_it->second.first);
            *_it->second.second = false;
        }
        // Check this thread's status
        bool this_thread_is_running() {
            lock_guard<mutex> _(info_mutex_);
            auto _it = info_map_.find(this_thread::get_id());
            if ( _it == end(info_map_) ) { return false; }
            lock_guard<mutex> __(*_it->second.first);
            return *_it->second.second;
        }
    };

    inline void register_this_thread() {
        thread_info::instance().register_this_thread();
    }

    // Unregister current thread and release the resource
    // then can join the thread.
    inline void unregister_this_thread() {
        thread_info::instance().unregister_this_thread();
    }

    // Stop all thread registered
    inline void join_all_threads() {
        thread_info::instance().join_all_threads();
    }

    // join specified thread
    inline void safe_join_thread(thread::id tid) {
        thread_info::instance().safe_join_thread(tid);
    }

    // Check this thread's status
    inline bool this_thread_is_running() {
        return thread_info::instance().this_thread_is_running();
    }

    // Thread Agent to auto register and unregister the thread to the thread info map
    class thread_agent
    {
    public:
        thread_agent() { register_this_thread(); }
        ~thread_agent() { unregister_this_thread(); }
    };

    // The global server signal agent. should be the first line in any application
    class signal_agent
    {
    public:
        typedef function<void(void)>        before_exit_t;
    protected:
        before_exit_t                       exit_callback_;
    public:
        signal_agent(before_exit_t cb) : exit_callback_(cb) { set_signal_handler(); };
        ~signal_agent() {
            wait_for_exit_signal();
            if ( exit_callback_ ) exit_callback_() ;
            join_all_threads();
        }
        static void quit() {
            send_exit_signal();
        }
    };

    template < class Item > class event_pool
    {
    public:
        typedef function<void()>                action_void_t;
        typedef function<bool(bool)>            action_bool_t;
    	typedef function<void(Item&&)>	        get_event_t;
        typedef function<void(const Item&&)>    enum_event_t;
        typedef function<bool(Item&&)>          find_event_t;
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

        template < typename Container, typename Locker >
        void notify_lots(const Container &itemList, Locker *locker = NULL, enum_event_t enum_callback = NULL) {
            unique_lock<mutex> _l(mutex_);
            if ( locker != NULL ) {
                locker->lock();
            }
            for ( auto && item : itemList ) {
                pool_.emplace(item);
                cv_.notify_one();
                if ( enum_callback ) enum_callback(move(item));
            }
            if ( locker != NULL ) {
                locker->unlock();
            }
        }

    	void clear() {
    		lock_guard<mutex> _l(mutex_);
    		pool_.clear();
    	}

        size_t size() {
            lock_guard<mutex> _l(mutex_);
            return pool_.size();
        }

        bool search_pending_event(action_void_t before, find_event_t find_event, action_bool_t after = NULL) {
            lock_guard<mutex> _l(mutex_);
            if ( before ) before();
            bool _search_ret = false;
            for ( auto &&_item : pool_ ) {
                if ( find_event(move(_item)) ) {
                    _search_ret = true;
                    break;
                }
            }
            if ( after ) _search_ret = after(_search_ret);
            return _search_ret;
        }
    };
}

#endif

// inc/log.hpp
#ifndef __CPP_UTILITY_LOG_H__
#define __CPP_UTILITY_LOG_H__

#include <iostream>
#include <ctime>
#include <chrono>
#include <fstream>
#include <syslog.h>
#include <mutex>
#include <assert.h>
#include <sstream>
#include <cstdarg>


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

    typedef pair<cp_log_level, string>  log_item_t;

    static inline const char *cp_log_lv_to_string(cp_log_level lv) {
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

    static inline void cp_log_get_time(string & logline) {
        auto _now = system_clock::now();
        auto _time_t = system_clock::to_time_t(_now);
        auto _time_point = _now.time_since_epoch();
        _time_point -= duration_cast<seconds>(_time_point); 
        auto _tm = localtime(&_time_t);
        size_t _current_sz = logline.size();
        logline.resize(_current_sz + 25);   // '[yyyy-MM-dd hh:mm:ss.zzz]'

        sprintf(&logline[_current_sz], "[%04d-%02d-%02d %02d:%02d:%02d.%03d]", 
                _tm->tm_year + 1900, _tm->tm_mon + 1, _tm->tm_mday,
                _tm->tm_hour, _tm->tm_min, _tm->tm_sec,
                static_cast<unsigned>(_time_point / milliseconds(1)));
    }


    class log_arguments {
    private:
        cp_log_level            log_lv;
        bool                    log_to_sys;
        string                  log_path;
        FILE*                   log_fp;
        thread*                 log_thread;
        event_pool<log_item_t>  log_pool;
        bool                    log_status;
        mutex                   log_mutex;

        log_arguments() : 
            log_lv(log_info), 
            log_to_sys(false),
            log_fp(NULL),
            log_thread(NULL),
            log_status(false)
        {
            log_thread = new thread([&](){
                thread_agent _ta;

                log_item_t _logitem;
                while ( this_thread_is_running() ) {
                    if ( !this->log_pool.wait_for(milliseconds(10), [&](log_item_t&& line){
                                _logitem.swap(line);
                            }) ) continue;
                    lock_guard<mutex> _(log_mutex);
                    if ( log_status == false ) continue;

                    if ( this->log_fp != NULL ) {
                        fprintf(this->log_fp, "%s\n", _logitem.second.c_str());
                    } else if ( this->log_to_sys ) {
                        // Syslog
                        syslog(_logitem.first, "%s\n", _logitem.second.c_str());
                    } else if ( this->log_path.size() > 0 ) {
                        // To file
                        do {
                            this->log_fp = fopen(this->log_path.c_str(), "a+");
                        } while ( this->log_fp == NULL && this_thread_is_running() );
                        fprintf(this->log_fp, "%s\n", _logitem.second.c_str());
                        fclose(this->log_fp);
                        this->log_fp = NULL;
                    }
                }
            });
        }

    public:
        ~log_arguments()
        {
            // Check and stop the log system
            //cp_log_stop();
            if ( log_thread != NULL ) {
                if ( log_thread->joinable() ) {
                    log_thread->join();
                }
                delete log_thread;
                log_thread = NULL;
            }

            if ( log_to_sys ) {
                closelog();
            }
            log_to_sys = false;
        }

        void start(const string &logpath, cp_log_level lv) {
            log_fp = NULL;
            log_path = logpath;
            log_lv = lv;
            log_to_sys = false;

            lock_guard<mutex> _(log_mutex);
            log_status = true;
        }

        void start(FILE *fp, cp_log_level lv) {
            log_fp = fp;
            log_lv = lv;
            log_path = "";
            log_to_sys = false;

            lock_guard<mutex> _(log_mutex);
            log_status = true;
        }

        void start(cp_log_level lv, const string& logname) {
            setlogmask(LOG_UPTO(lv));
            openlog(logname.c_str(), LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

            log_to_sys = true;
            log_lv = lv;
            log_fp = NULL;
            log_path = "";

            lock_guard<mutex> _(log_mutex);
            log_status = true;
        }

        void log(cp_log_level lv, const char *format, ...) {
            // Check log level
            if ( lv > log_lv ) return;
            if ( log_thread == NULL ) return;

            string _logline;
            if ( log_to_sys == false ) {
                cp_log_get_time(_logline);
            }
            _logline += "[";
            _logline += cp_log_lv_to_string(lv);
            _logline += "] ";

            va_list _va;
            va_start(_va, format);
            size_t _fmtsize = vsnprintf(NULL, 0, format, _va);
            va_end(_va);
            size_t _crtsize = _logline.size();
            _logline.resize(_crtsize + _fmtsize + 1);
            va_start(_va, format);
            vsnprintf(&_logline[_crtsize], _fmtsize + 1, format, _va);
            va_end(_va);

            log_pool.notify_one(make_pair(lv, _logline));
        }

        static log_arguments& instance() {
            static log_arguments _arg;
            return _arg;
        }
    };

    // The end line struct is just a place hold
    class cp_logger_specifical_character
    {
    protected:
        char                _sc;
        friend ostream & operator << (ostream &os, const cp_logger_specifical_character & sc );
    public:
        // True : the character should be add to the log line
        // False: this is the end of log line.
        operator bool () const {
            return (_sc != '\0');
        }

        cp_logger_specifical_character( char c = '\n' ) : _sc(c) { }
        cp_logger_specifical_character( bool eol ) : _sc('\0') {
            if ( eol == false ) _sc = '\n';
        }

        // Get the char as a function object
        char operator() (void) const {
            return _sc;
        }
    };

    // Output the specifical chararcter
    inline ostream & operator << (ostream &os, const cp_logger_specifical_character & sc ) {
        if ( sc ) {
            os << sc._sc;
        }
        return os;
    }

    // Stream logger
    class cp_logger
    {
    protected:
        cp_log_level            lv_;
        recursive_mutex         mutex_;
        ostringstream           oss_;
        uint32_t                lock_level_;

        template< class T >
        friend cp_logger & operator << (cp_logger & logger, const T & item);
    public:
        cp_logger(cp_log_level lv) : lv_(lv), lock_level_(0) { }

    public:
        // Log object
        static cp_logger& emergancy() {
            static cp_logger _obj(log_emergancy);
            return _obj;
        }
        static cp_logger& alert() {
            static cp_logger _obj(log_alert);
            return _obj;
        }
        static cp_logger& critical() {
            static cp_logger _obj(log_critical);
            return _obj;
        }
        static cp_logger& error() {
            static cp_logger _obj(log_error);
            return _obj;
        }
        static cp_logger& warning() {
            static cp_logger _obj(log_warning);
            return _obj;
        }
        static cp_logger& notice() {
            static cp_logger _obj(log_notice);
            return _obj;
        }
        static cp_logger& info() {
            static cp_logger _obj(log_info);
            return _obj;
        }
        static cp_logger& debug() {
            static cp_logger _obj(log_debug);
            return _obj;
        }

        // End of current log line
        static cp_logger_specifical_character& endl() {
            static cp_logger_specifical_character _obj('\0');
            return _obj;
        }
        static cp_logger_specifical_character& newline() {
            static cp_logger_specifical_character _obj('\n');
            return _obj;
        }
        static cp_logger_specifical_character& backspace() {
            static cp_logger_specifical_character _obj('\b');
            return _obj;
        }
        static cp_logger_specifical_character& tab() {
            static cp_logger_specifical_character _obj('\t');
            return _obj;
        }

    public:
        static void start(const string &logpath, cp_log_level lv) {
            log_arguments::instance().start(logpath, lv);
        }
        static void start(FILE *fp, cp_log_level lv) {
            log_arguments::instance().start(fp, lv);
        }
        static void start(cp_log_level lv, const string& logname) {
            log_arguments::instance().start(lv, logname);
        }
    };

    template < class T > 
    inline cp_logger & operator << ( cp_logger& logger, const T & item ) {
        // Lock the log object
        logger.mutex_.lock();
        logger.lock_level_ += 1;

        // Append the buffer
        logger.oss_ << item;

        if ( logger.lock_level_ > 1 ) {
            logger.lock_level_ -=1;
            logger.mutex_.unlock();
        }
        return logger;
    }

    template < >
    inline cp_logger & operator << <cp_logger_specifical_character> ( 
        cp_logger& logger, const cp_logger_specifical_character & item ) {
        if ( item ) {
            return logger << item();
        }
        // Write the log
        log_arguments::instance().log(logger.lv_, "%s", logger.oss_.str().c_str());
        logger.oss_.str("");
        logger.oss_.clear();

        logger.lock_level_ -= 1;
        assert(logger.lock_level_ == 0);
        logger.mutex_.unlock();
        return logger;
    }

    #define lend                cp_logger::endl()
    #define lnewl               cp_logger::newline()
    #define lbackspace          cp_logger::backspace()
    #define ltab                cp_logger::tab()
    #define lemergancy          cp_logger::emergancy()
    #define lalert              cp_logger::alert()
    #define lcritical           cp_logger::critical()
    #define lerror              cp_logger::error()
    #define lwarning            cp_logger::warning()
    #define lnotice             cp_logger::notice()
    #define linfo               cp_logger::info()
    #define ldebug              cp_logger::debug()
}

#endif // cpputility.log.h

// inc/string_format.hpp
#ifndef __CPP_UTILITY_STRING_FORMAT_HPP__
#define __CPP_UTILITY_STRING_FORMAT_HPP__

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <stdio.h>
#include <string.h>

using namespace std;

namespace cpputility
{
    // trim from start
    static inline std::string &ltrim(std::string &s) {
        s.erase(
            s.begin(), 
            std::find_if(
                s.begin(), 
                s.end(), 
                std::not1(std::ptr_fun<int, int>(std::isspace))
                )
            );
        return s;
    }

    // trim from end
    static inline std::string &rtrim(std::string &s) {
        s.erase(
            std::find_if(
                s.rbegin(), 
                s.rend(), 
                std::not1(std::ptr_fun<int, int>(std::isspace))
                ).base(), 
            s.end()
            );
        return s;
    }

    // trim from both ends
    static inline std::string &trim(std::string &s) {
        return ltrim(rtrim(s));
    }

    // Split a string with the char in the carry.
    static inline void split_string( const std::string &value, 
        const std::string &carry, std::vector<std::string> &component )
    {
        if ( value.size() == 0 ) return;
        std::string::size_type _pos = 0;
        do {
            std::string::size_type _lastPos = std::string::npos;
            for ( std::string::size_type i = 0; i < carry.size(); ++i ) {
                std::string::size_type _nextCarry = value.find( carry[i], _pos );
                _lastPos = (_nextCarry < _lastPos) ? _nextCarry : _lastPos;
            }
            if ( _lastPos == std::string::npos ) _lastPos = value.size();
            if ( _lastPos > _pos ) {
                std::string _com = value.substr( _pos, _lastPos - _pos );
                component.push_back(_com);
            }
            _pos = _lastPos + 1;
        } while( _pos < value.size() );
    }

    // Dump binary packet with HEX
    static inline void dump_hex(const char *data, unsigned int length, FILE *of = stdout) {
        const static unsigned int g_char_per_line = 16;
        const static unsigned int g_addr_size = sizeof(intptr_t) * 2 + 2;
        const static unsigned int g_line_buf_size = g_char_per_line * 4 + 3 + g_addr_size + 2;
        unsigned int _lines = (length / g_char_per_line) + ((length % g_char_per_line) > 0 ? 1 : 0);
        unsigned int _last_line_size = (_lines == 1) ? length : length % g_char_per_line;
        if ( _last_line_size == 0 ) _last_line_size = g_char_per_line;

        // Create the buffer
        string _buf_line_str;
        _buf_line_str.resize(g_line_buf_size);
        char *_buf = &_buf_line_str[0];

        // Loop to output the data
        for ( unsigned int _l = 0; _l < _lines; ++_l ) { // for each line
            unsigned int _line_size = (_l == _lines - 1) ? _last_line_size : g_char_per_line;
            memset( _buf, 0x20, g_line_buf_size );
            if ( sizeof(intptr_t) == 4 ) {  // 32bits
                sprintf( _buf, "%08x: ", (unsigned int)(intptr_t)(data + (_l * g_char_per_line)) );
            } else {  // 64bits
                sprintf( _buf, "%016lx: ", (unsigned long)(intptr_t)(data + (_l * g_char_per_line)) );
            }

            for ( unsigned int _c = 0; _c < _line_size; ++_c ) {
                sprintf( _buf + _c * 3 + g_addr_size, "%02x ", 
                    (unsigned char)data[_l * g_char_per_line + _c]
                );
                _buf[ (_c + 1) * 3 + g_addr_size ] = ' ';  // Reset the '\0'
                _buf[ g_char_per_line * 3 + 1 + _c + g_addr_size + 1 ] = 
                    ( (isprint((unsigned char)(data[_l * g_char_per_line + _c])) ?
                        data[_l * g_char_per_line + _c] : '.')
                    );
            }
            _buf[ g_char_per_line * 3 + g_addr_size ] = '\t';
            _buf[ g_char_per_line * 3 + g_addr_size + 1 ] = '|';
            _buf[ g_line_buf_size - 3 ] = '|';
            _buf[ g_line_buf_size - 2 ] = '\0';
            fprintf(of, "%s\n", _buf);
        }
    }

    static inline void dump_hex(const string &buffer, FILE *of = stdout) {
        dump_hex(buffer.c_str(), buffer.size(), of);
    }
}

#endif

// inc/socket.h
#ifndef __SOCK_LITE_SOCKET_H__
#define __SOCK_LITE_SOCKET_H__

#if ( defined WIN32 | defined _WIN32 | defined WIN64 | defined _WIN64 )
    #define _SL_PLATFORM_WIN      1
#elif TARGET_OS_WIN32
    #define _SL_PLATFORM_WIN      1
#elif defined __CYGWIN__
    #define _SL_PLATFORM_WIN      1
#else
    #define _SL_PLATFORM_WIN      0
#endif
#ifdef __APPLE__
    #define _SL_PLATFORM_MAC      1
#else
    #define _SL_PLATFORM_MAC      0
#endif
#if _SL_PLATFORM_WIN == 0 && _SL_PLATFORM_MAC == 0
    #define _SL_PLATFORM_LINUX    1
#else
    #define _SL_PLATFORM_LINUX    0
#endif
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    #define _SL_PLATFORM_IOS      1
#else
    #define _SL_PLATFORM_IOS      0
#endif

#define SL_TARGET_WIN32  (_SL_PLATFORM_WIN == 1)
#define SL_TARGET_LINUX  (_SL_PLATFORM_LINUX == 1)
#define SL_TARGET_MAC    (_SL_PLATFORM_MAC == 1)
#define SL_TARGET_IOS    (_SL_PLATFORM_IOS == 1)

#if SL_TARGET_WIN32
// Disable the certain warn in Visual Studio for old functions.
#pragma warning (disable : 4996)
#pragma warning (disable : 4251)

#endif

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <wchar.h>
#include <wctype.h>
#include <stddef.h>
#include <math.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <iostream>
#include <map>

#include <iostream>
#include <string>
using namespace std;

#if SL_TARGET_WIN32
#include <WinSock2.h>
#include <Windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <stddef.h>
#include <sys/time.h>
#endif

// Use the Cpp Utility Log

using namespace cpputility;

// Linux Thread, pit_t
#if SL_TARGET_LINUX
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#define gettid()    syscall(__NR_gettid)
#endif

// For Mac OS X
#ifdef __APPLE__
#include <libkern/OSAtomic.h>
#include <unistd.h>
#include <sys/syscall.h>
#define gettid()    syscall(SYS_gettid)
#endif

#if SL_TARGET_WIN32
    #include <WS2tcpip.h>
    #pragma comment( lib, "Ws2_32.lib" )
    #define SL_NETWORK_NOSIGNAL           0
    #define SL_NETWORK_IOCTL_CALL         ioctlsocket
    #define SL_NETWORK_CLOSESOCK          ::closesocket
#else 
    #include <sys/socket.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <netinet/tcp.h>
    #define SL_NETWORK_NOSIGNAL           MSG_NOSIGNAL
    #define SL_NETWORK_IOCTL_CALL         ioctl
    #define SL_NETWORK_CLOSESOCK          ::close
#endif

#if SL_TARGET_MAC
    #undef  SL_NETWORK_NOSIGNAL
    #define SL_NETWORK_NOSIGNAL           0
#endif

typedef enum {
    SO_INVALIDATE       = -1,
    SO_IDLE             = 0,
    SO_OK               = 1
} SOCKETSTATUE;

typedef enum {
	SO_READ_WAITING		= 0x0000,
	SO_READ_CLOSE		= 0x0001,	// recv return code < 0
	SO_READ_TIMEOUT		= 0x0002,	// select time out
	SO_READ_DONE		= 0x0004,	// get incoming data
	SO_READ_TIMEOUT_AND_UNFINISH	= SO_READ_DONE | SO_READ_TIMEOUT,
	SO_READ_DONE_BUT_CLOSED			= SO_READ_DONE | SO_READ_CLOSE,
} SO_READ_STATUE;

typedef enum {
    SO_CHECK_WRITE      = 1,
    SO_CHECK_READ       = 2,
    SO_CHECK_CONNECT    = SO_CHECK_WRITE | SO_CHECK_READ
} SOCKETOPT;

typedef long SOCKET_T;

#ifndef INVALIDATE_SOCKET
#define INVALIDATE_SOCKET           ((long)((long)0 - (long)1))
#endif

#define SOCKET_NOT_VALIDATE( so )   ((so) == INVALIDATE_SOCKET)
#define SOCKET_VALIDATE( so )       ((so) != INVALIDATE_SOCKET)

// In No-Windows
#ifndef FAR
#define FAR
#endif

#ifndef __SOCKET_SERVER_INIT_IN_WINDOWS__
#define __SOCKET_SERVER_INIT_IN_WINDOWS__
#if SL_TARGET_WIN32

// In Windows Only.
// This class is used to initialize the WinSock Server.
// A global instance of this object will be create and
// provide nothing. only the c'str of this object
// will invoke WSAStartup and the d'str will invoke 
// WSACleanup.
// In Linux or other platform, this object will not be
// defined.
template< int __TMP_VALUE__ = 0 >
class __socket_init_svr_in_windows
{
    __socket_init_svr_in_windows< __TMP_VALUE__ >()
    {
        WSADATA v_wsaData;
        WORD v_wVersionRequested;

        v_wVersionRequested = MAKEWORD(1, 1);
        WSAStartup(v_wVersionRequested, &v_wsaData);
    }

public:
    ~__socket_init_svr_in_windows< __TMP_VALUE__ >()
    {
        WSACleanup();
    }
    static __socket_init_svr_in_windows< __TMP_VALUE__ > __g_socksvrInWindows;
};

template< > __socket_init_svr_in_windows< 0 > 
__socket_init_svr_in_windows< 0 >::__g_socksvrInWindows;

#endif
#endif

// Translate Domain to IP Address
char * network_domain_to_ip(const char * domain, char * output, unsigned int length);

// Translate Domain to InAddr
unsigned int network_domain_to_inaddr(const char * domain);

// Translate the ip string to an InAddr
uint32_t network_ipstring_to_inaddr(const string &ipaddr);

// Translate the InAddr to an Ip string
void network_inaddr_to_string(uint32_t inaddr, string &ipstring);

// Get localhost's computer name on LAN.
void network_get_localhost_name( string &hostname );

// Convert the uint ip addr to human readable ip string.
void network_int_to_ipaddress( const uint32_t ipaddr, string &ip );

// Get peer ipaddress and port from a specified socket handler.
void network_peer_info_from_socket( const SOCKET_T hSo, uint32_t &ipaddr, uint32_t &port );

// Get current socket's port info
void network_sock_info_from_socket( const SOCKET_T hSo, uint32_t &port );

// Check the specified socket's status according to the option.
SOCKETSTATUE socket_check_status( SOCKET_T hSo, SOCKETOPT option = SO_CHECK_READ, uint32_t waitTime = 0 );

// Set the linger time for a socket, I strong suggest not to change this value unless you 
// know what you are doing
bool socket_set_linger_time(SOCKET_T so, bool onoff = true, unsigned timeout = 1);

/*!
The IP object, compatible with std::string and uint32_t
This is a ipv4 ip address class.
*/
class sl_ip {
    string          ip_;

public:
    sl_ip();
    sl_ip(const sl_ip& rhs);

    // Conversition
    sl_ip(const string &ipaddr);
    sl_ip(uint32_t ipaddr);
    operator uint32_t() const;
    operator string&();
    operator string() const;
    operator const string&() const;
    operator const char *() const;
    const char *c_str() const;
    size_t size() const;

    // Cast operator
    sl_ip & operator = (const string &ipaddr);
    sl_ip & operator = (uint32_t ipaddr);

    // Operators
    bool operator == (const sl_ip& rhs) const;
    bool operator != (const sl_ip& rhs) const;
    bool operator <(const sl_ip& rhs) const;
    bool operator >(const sl_ip& rhs) const;
    bool operator <=(const sl_ip& rhs) const;
    bool operator >=(const sl_ip& rhs) const;
};

// Output
ostream & operator << (ostream &os, const sl_ip & ip);

/*!
Peer Info, contains an IP address and a port number.
should be output in the following format: 0.0.0.0:0
*/
class sl_peerinfo {
    sl_ip           ip_;
    uint16_t        port_;
    string          format_;
public:
    const sl_ip &       ipaddress;
    const uint16_t &    port_number;

    void parse_peerinfo_from_string(const string &format_string);
    void set_peerinfo(const string &ipaddress, uint16_t port);
    void set_peerinfo(uint32_t inaddr, uint16_t port);

    sl_peerinfo();
    sl_peerinfo(uint32_t inaddr, uint16_t port);
    sl_peerinfo(const string &format_string);
    sl_peerinfo(const string &ipaddr, uint16_t port);
    sl_peerinfo(const sl_peerinfo& rhs);
    sl_peerinfo & operator = (const sl_peerinfo& rhs);
    sl_peerinfo & operator = (const string &format_string);

    operator bool() const;
    operator const string () const;
    operator const char *() const;
    const char *c_str() const;
    size_t size() const;

    // Get an empty peer info
    static const sl_peerinfo & nan();
};

// Output the peer info
ostream & operator << (ostream &os, const sl_peerinfo &peer);

/*
IP Range, x.x.x.x/n
*/
class sl_iprange {
private:
    uint32_t        low_;
    uint32_t        high_;

    void parse_range_from_string(const string &format_string);
public:
    sl_iprange();
    sl_iprange(const string & format_string);
    sl_iprange(uint32_t low, uint32_t high);
    sl_iprange(const sl_iprange &rhs);

    sl_iprange & operator = (const sl_iprange & rhs);
    sl_iprange & operator = (const string & format_string);

    operator bool() const;
    operator const string() const;
    bool is_ip_in_range(const sl_ip& ip);
};

// Output the ip range
ostream & operator << (ostream &os, const sl_iprange &range);


// The basic virtual socket class
class sl_socket
{
protected:
    bool m_iswrapper;
    bool m_is_listening;
public:
    // The socket handler
    SOCKET_T  m_socket;

    sl_socket(bool iswrapper = false);
    virtual ~sl_socket();
    // Connect to peer
    virtual bool connect( const uint32_t inaddr, uint32_t port, uint32_t timeout = 1000 ) = 0;
    virtual bool connect( const sl_ip& ip, uint32_t port, uint32_t timeout = 1000 ) = 0;
    virtual bool connect( const sl_peerinfo &peer, uint32_t timeout = 1000 ) = 0;
    virtual bool connect( const string &ipaddr, uint32_t port, uint32_t timeout = 1000 ) = 0;
    // Listen on specified port and address, default is 0.0.0.0
    virtual bool listen( uint32_t port, uint32_t ipaddr = INADDR_ANY ) = 0;
    // Close the connection
    void close();
    // When the socket is a listener, use this method 
    // to accept client's connection.
    //virtual sl_socket *get_client( uint32_t timeout = 100 ) = 0;
    //virtual void release_client( sl_socket *client ) = 0;

    // Set current socket reusable or not
    bool set_reusable( bool reusable = true );
    // Enable TCP_KEEPALIVE or not
    bool set_keepalive( bool keepalive = true );
    // Set the socket to be non-block
    bool set_nonblocking( bool nonblocking = true );
    // Set socket buffer, 0 means remine default
    bool set_socketbufsize( unsigned int rmem = 0, unsigned int wmem = 0 );

    // Add current socket to the async monitor, current sl_socket
    // will be set to wrapper automatically.9
    virtual void monitor() = 0;

    virtual void dump();

    // Read data from the socket until timeout or get any data.
    virtual SO_READ_STATUE read_data( string &buffer, uint32_t timeout = 1000 ) = 0;

    // Write data to peer.
    virtual bool write_data( const string &data ) = 0;
};

#endif 

// inc/dns.h
#ifndef __CLEAN_DNS_DNS_PACKAGE_H__
#define __CLEAN_DNS_DNS_PACKAGE_H__

#define SOCK_LITE_INTEGRATION_DNS

#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>

using namespace std;

// DNS Question Type
typedef enum {
    sl_dns_qtype_host           = 0x01,     // Host(A) record
    sl_dns_qtype_ns             = 0x02,     // Name server (NS) record
    sl_dns_qtype_cname          = 0x05,     // Alias(CName) record
    sl_dns_qtype_ptr            = 0x0C,     // Reverse-lookup(PTR) record
    sl_dns_qtype_mx             = 0x0F,     // Mail exchange(MX) record
    sl_dns_qtype_srv            = 0x21,     // Service(SRV) record
    sl_dns_qtype_ixfr           = 0xFB,     // Incremental zone transfer(IXFR) record
    sl_dns_qtype_axfr           = 0xFC,     // Standard zone transfer(AXFR) record
    sl_dns_qtype_all            = 0xFF      // All records
} sl_dns_qtype;

// DNS Question Class
typedef enum {
    sl_dns_qclass_in            = 0x0001,   // Represents the IN(internet) question and is normally set to 0x0001
    sl_dns_qclass_ch            = 0x0003,   // the CHAOS class
    sl_dns_qclass_hs            = 0x0004    // Hesiod   
} sl_dns_qclass;

typedef enum {
    sl_dns_opcode_standard      = 0,
    sl_dns_opcode_inverse       = 1,
    sl_dns_opcode_status        = 2,
    sl_dns_opcode_reserved_3    = 3,    // not use
    sl_dns_opcode_notify        = 4,        // in RFC 1996
    sl_dns_opcode_update        = 5         // in RFC 2136
} sl_dns_opcode;

typedef enum {
    sl_dns_rcode_noerr              = 0,
    sl_dns_rcode_format_error       = 1,
    sl_dns_rcode_server_failure     = 2,
    sl_dns_rcode_name_error         = 3,
    sl_dns_rcode_not_impl           = 4,
    sl_dns_rcode_refuse             = 5,
    sl_dns_rcode_yxdomain           = 6,
    sl_dns_rcode_yxrrset            = 7,
    sl_dns_rcode_nxrrset            = 8,
    sl_dns_rcode_notauth            = 9,
    sl_dns_rcode_notzone            = 10,
    sl_dns_rcode_badvers            = 16,
    sl_dns_rcode_badsig             = 16,
    sl_dns_rcode_badkey             = 17,
    sl_dns_rcode_badtime            = 18,
    sl_dns_rcode_badmode            = 19,
    sl_dns_rcode_badname            = 20,
    sl_dns_rcode_badalg             = 21
} sl_dns_rcode;

#pragma pack(push, 1)
class sl_dns_packet {

    enum { packet_header_size = sizeof(uint16_t) * 6 };
protected:
    string          packet_data_;
public:
    // Properties

    // Trans-Action ID
    uint16_t        get_transaction_id() const;
    void            set_transaction_id(uint16_t tid);

    // Request Type
    bool            get_is_query_request() const;
    bool            get_is_response_request() const;
    void            set_is_query_request(bool isqr = true);

    // Operator Code
    sl_dns_opcode   get_opcode() const;
    void            set_opcode(sl_dns_opcode opcode = sl_dns_opcode_standard);

    // If this is an authoritative answer
    bool            get_is_authoritative() const;
    void            set_is_authoritative(bool auth = false);

    // If current packet is truncation
    bool            get_is_truncation() const;
    void            set_is_truncation(bool trunc = true);

    // If the request need recursive query.
    bool            get_is_recursive_desired() const;
    void            set_is_recursive_desired(bool rd = true);

    // If current server support recursive query
    bool            get_is_recursive_available() const;
    void            set_is_recursive_available(bool recursive = true);

    // Get the response code
    sl_dns_rcode    get_resp_code() const;
    void            set_resp_code(sl_dns_rcode rcode = sl_dns_rcode_noerr);

    uint16_t        get_qd_count() const;
    uint16_t        get_an_count() const;
    uint16_t        get_ns_count() const;
    uint16_t        get_ar_count() const;

    // Constructures
    sl_dns_packet();
    sl_dns_packet(const sl_dns_packet& rhs);
    sl_dns_packet(const sl_dns_packet&& rrhs);
    sl_dns_packet(const string& packet, bool is_tcp_packet = false);
    sl_dns_packet(uint16_t trans_id, const string& query_domain);

    // Operators
    sl_dns_packet& operator = (const sl_dns_packet& rhs);
    sl_dns_packet& operator = (const sl_dns_packet&& rhs);

    // Parse the query domain
    // The query domain seg will store the domain in the following format:
    // [length:1Byte][component][length:1Byte][component]...
    const string get_query_domain() const;
    // This method will auto increase the packet size
    void set_query_domain(const string& domain, sl_dns_qtype qtype = sl_dns_qtype_host, sl_dns_qclass qclass = sl_dns_qclass_in);

    // Dump all A-Records in the dns packet
    const vector<sl_ip> get_A_records() const;
    // Add a records to the end of the dns packet
    void set_A_records(const vector<sl_ip> & a_records);

    // Dump all C-Name Records in the dns packet
    const vector<string> get_C_Names() const;
    // Append C-Name to the end of the dns packet
    void set_C_Names(const vector<string> & c_names);

    // The size of the packet
    size_t size() const;
    // The buffer point of the packet
    const char *const pbuf();

    // Cast to string
    operator const string&() const;
    const string& str() const;

    // Convert current packet to tcp packet
    const string to_tcp_packet() const;
};

#pragma pack(pop)

#endif

// inc/poller.h
#ifndef __SOCK_LITE_POLLER_H__
#define __SOCK_LITE_POLLER_H__

    
#if SL_TARGET_LINUX
#include <sys/epoll.h>
#elif SL_TARGET_MAC
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>
#endif

#include <vector>
#include <map>
#include <unordered_map>

#define CO_MAX_SO_EVENTS		1024

// All Socket Event
enum SL_EVENT_ID {
    SL_EVENT_ACCEPT         = 0x01,
    SL_EVENT_DATA           = 0x02,     // READ
    SL_EVENT_READ           = 0x02,
    SL_EVENT_FAILED         = 0x04,
    SL_EVENT_CONNECT        = 0x08,
    SL_EVENT_WRITE          = 0x08,     // Write and connect is the same
    SL_EVENT_TIMEOUT        = 0x10,

    SL_EVENT_DEFAULT        = (SL_EVENT_ACCEPT | SL_EVENT_DATA | SL_EVENT_FAILED),
    SL_EVENT_ALL            = 0x1F
};

// Convert the EVENT_ID to string
const string sl_event_name(uint32_t eid);

/*
    The event structure for a system epoll/kqueue to set the info
    of a socket event.

    @so: the socket you should act some operator on it.
    @source: the tcp listening socket which accept current so, 
        in udp socket or other events of tcp socket, source will
        be an INVALIDATE_SOCKET
    @event: the event current socket get.
    @socktype: IPPROTO_TCP or IPPROTO_UDP
    @address: the address info of a udp socket when it gets some
        incoming data, otherwise it will be undefined.
*/
typedef struct tag_sl_event {
    SOCKET_T                so;
    SOCKET_T                source;
    SL_EVENT_ID             event;
    int                     socktype;
    struct sockaddr_in      address;    // For UDP socket usage.
} sl_event;

/*
    Output of the event
    The format will be:
        "event SL_EVENT_xxx SL_EVENT_xxx for xxx socket <so>"
*/
ostream & operator << (ostream &os, const sl_event & e);

// Create a failed or timedout event structure object
sl_event sl_event_make_failed(SOCKET_T so = INVALIDATE_SOCKET);
sl_event sl_event_make_timeout(SOCKET_T so = INVALIDATE_SOCKET);

/*
    Epoll|Kqueue Manager Class
    The class is a singleton class, the whole system should only
    create one epoll|kqueue file descriptor to monitor all sockets
    or file descriptors

*/
class sl_poller
{
public:
    // Event list type.
	typedef std::vector<sl_event>	earray;
protected:
	int 				m_fd;
#if SL_TARGET_LINUX
	struct epoll_event	*m_events;
#elif SL_TARGET_MAC
	struct kevent		*m_events;
#endif

    // TCP Listening Socket Map
	unordered_map<SOCKET_T, bool>       m_tcp_svr_map;

    // Timeout Info
    unordered_map<SOCKET_T, time_t>     m_timeout_map;
    mutex                               m_timeout_mutex;

protected:
    // Cannot create a poller object, it should be a Singleton instance
	sl_poller();
public:
	~sl_poller();
        
	// Bind the server side socket
	bool bind_tcp_server( SOCKET_T so );

	// Try to fetch new events(Only return SL_EVENT_DEFAULT)
	size_t fetch_events( earray &events,  unsigned int timedout = 1000 );

	// Start to monitor a socket hander
	// In default, the poller will maintain the socket infinite, if
	// `oneshot` is true, then will add the ONESHOT flag
    // Default time out of a socket in epoll/kqueue will be 30 seconds
	bool monitor_socket(  
        SOCKET_T so, 
        bool oneshot = false, 
        uint32_t eid = SL_EVENT_DEFAULT, 
        uint32_t timedout = 30 
    );

	// Singleton Poller Item
	static sl_poller &server();
};

#endif

// inc/events.h
#ifndef __SOCK_LITE_EVENTS_H__
#define __SOCK_LITE_EVENTS_H__

#include <unordered_map>

// The socket event handler
//typedef void (*sl_socket_event_handler)(sl_event);
typedef std::function<void(sl_event)>   sl_socket_event_handler;

// The callback function for each run loop
//typedef void (*sl_runloop_callback)(void);
typedef std::function<void(void)>       sl_runloop_callback;

typedef struct tag_sl_handler_set {
    sl_socket_event_handler         on_accept;
    sl_socket_event_handler         on_data;
    sl_socket_event_handler         on_failed;
    sl_socket_event_handler         on_write;
    sl_socket_event_handler         on_timedout;
} sl_handler_set;

/*
    Event Run Loop Class
    This class is a singleton. It will fetch the Poller every 
    <timespice> milleseconds.

    The class has at least one worker thread, and will auto increase
    or decrease according to the pending unprocessed events.
*/
class sl_events
{
public:
    typedef union {
        struct {
            uint32_t    timeout;
            uint32_t    eventid;
        } flags;
        uint64_t        event_info;
    } event_mask;

    // Return an empty handler set 
    static sl_handler_set empty_handler();

    // Socket Handler Set Map Type
    typedef map<SOCKET_T, sl_handler_set>       shsmap_t;

    // Socket Event Mask Map Type
    typedef unordered_map<SOCKET_T, event_mask> semmap_t;

protected:
    // Protected constructure
    sl_events();

    // Any action associates with the events or event handler
    // need to lock this mutex.
    mutable mutex           handler_mutex_;
    // Any validate socket need to bind en empty handler set to
    // sl_events, this map is used to store the relation between
    // a socket fd and a handler set.
    shsmap_t                handler_map_;

    // Any action associates with the event mask need to lock this mutex
    mutable mutex           event_mutex_;
    // Before monitor, before fetching, and after fetching, 
    // will re-order this map for all monitoring events.
    semmap_t                event_unprocessed_map_;
    semmap_t                event_unfetching_map_;

    // Internal Run Loop Properties.
    // Change of time piece and runloop callback should lock this
    // mutex at the first line
    mutable mutex           running_lock_;
    // Fetching Epoll/Kqueue's timeout setting
    uint32_t                timepiece_;
    // Callback method after each fetching action.
    sl_runloop_callback     rl_callback_;

    // Internal Runloop Working Thread.
    // This is the main thread object of Event System.
    thread *                runloop_thread_;

    // Manager Thread Info
    // All pending events are in this pool.
    event_pool<sl_event>    events_pool_;
    // Working thread poll
    vector<thread*>         thread_pool_;
    // Working thread monitor manager thread.
    thread *                thread_pool_manager_;

    // Start the Internal Run Loop Thread use the method: _internal_runloop
    void _internal_start_runloop();
    // The working thread method of the event runloop.
    void _internal_runloop();

    // Add a new worker to the thread pool and fetch pending
    // event from event_pool_
    void _internal_add_worker();
    // Remove the last worker from the thread pool
    void _internal_remove_worker();
    // The worker thread method.
    void _internal_worker();

    // Replace a hander of a socket's specified Event ID, return the old handler
    sl_socket_event_handler _replace_handler(SOCKET_T so, uint32_t eid, sl_socket_event_handler h);
    // Fetch the handler of a socket's specified Event ID, remine the old handler unchanged.
    sl_socket_event_handler _fetch_handler(SOCKET_T so, SL_EVENT_ID eid);
    // Check if the socket has the handler of specified Event ID
    bool _has_handler(SOCKET_T so, SL_EVENT_ID eid);
public:

    ~sl_events();

    // return the singleton instance of sl_events
    static sl_events& server();

    // Bind a handler set to a socket
    void bind( SOCKET_T so, sl_handler_set&& hset );
    // Remove the handler set of a socket
    void unbind( SOCKET_T so );
    // Update the handler of a specified event id.
    void update_handler( SOCKET_T so, uint32_t eid, sl_socket_event_handler&& h);
    // Append a handler to current handler set
    void append_handler( SOCKET_T so, uint32_t eid, sl_socket_event_handler h);
    // Check if the socket has specified event id's handler.    
    bool has_handler(SOCKET_T so, SL_EVENT_ID eid);

    // Monitor the socket for specified event.
    void monitor(SOCKET_T so, SL_EVENT_ID eid, sl_socket_event_handler handler, uint32_t timedout = 30);

    // Add an event to the socket's pending event pool.
    void add_event(sl_event && e);
    // Add a tcp socket's event, everything else in sl_event struct will be remined un-defined.
    void add_tcpevent(SOCKET_T so, SL_EVENT_ID eid);
    // Add a udp socket's event, evenything else in sl_event struct will be remined un-defined.
    void add_udpevent(SOCKET_T so, struct sockaddr_in addr, SL_EVENT_ID eid);

    // Setup the timepiece and callback method.
    void setup( uint32_t timepiece = 10, sl_runloop_callback cb = NULL );
};

#endif

// inc/socks5.h
#ifndef __SOCKLITE_SOCKS_5_H__
#define __SOCKLITE_SOCKS_5_H__


#include <functional>

enum sl_methods {
	sl_method_noauth		= 0,
	sl_method_gssapi		= 1,
	sl_method_userpwd		= 2,
	sl_method_nomethod		= 0xff
};

enum sl_socks5cmd {
	sl_socks5cmd_connect	= 1,
	sl_socks5cmd_bind		= 2,
	sl_socks5cmd_udp		= 3
};

enum sl_socks5atyp {
	sl_socks5atyp_ipv4		= 1,
	sl_socks5atyp_dname		= 3,
	sl_socks5atyp_ipv6		= 4,
};

enum sl_socks5rep {
	sl_socks5rep_successed			= 0,	// successed
	sl_socks5rep_failed				= 1,	// general SOCKS server failure
	sl_socks5rep_connectnotallow	= 2,	// connection not allowed by ruleset
	sl_socks5rep_unreachable		= 3,	// Network unreachable
	sl_socks5rep_hostunreachable	= 4,	// Host unreachable
	sl_socks5rep_refused			= 5,	// Connection refused
	sl_socks5rep_expired			= 6,	// TTL expired
	sl_socks5rep_notsupport			= 7,	// Command not supported
	sl_socks5rep_erroraddress		= 8,	// Address type not supported
};

static inline const char *sl_socks5msg(sl_socks5rep rep) {
	static const char * _gmsg[] = {
		"successed",
		"general SOCKS server failure",
		"connection not allowed by ruleset",
		"Network unreachable",
		"Host unreachable",
		"Connection refused",
		"TTL expired",
		"Command not supported",
		"Address type not supported",
		"Unknow Error Code"
	};
	if ( rep > sl_socks5rep_erroraddress ) return _gmsg[sl_socks5rep_erroraddress + 1];
	return _gmsg[rep];
};

#pragma pack(push, 1)
struct sl_socks5_packet {
	uint8_t 	ver;

	// Default we only support version 5
	sl_socks5_packet() : ver(5) {}
};

struct sl_socks5_handshake_request : public sl_socks5_packet {
	uint8_t		nmethods;
};

struct sl_socks5_noauth_request : public sl_socks5_handshake_request {
	uint8_t 	method;

	sl_socks5_noauth_request(): 
		sl_socks5_handshake_request(), method(sl_method_noauth) {
		nmethods = 1;
		}
};

struct sl_socks5_gssapi_request : public sl_socks5_handshake_request {
	uint8_t		method;

	sl_socks5_gssapi_request():
		sl_socks5_handshake_request(), method(sl_method_gssapi) {
		nmethods = 1;
		}
};

struct sl_socks5_userpwd_request : public sl_socks5_handshake_request {
	uint8_t		method;

	sl_socks5_userpwd_request():
		sl_socks5_handshake_request(), method(sl_method_userpwd) {
		nmethods = 1;
		}
};

struct sl_socks5_handshake_response : public sl_socks5_packet {
	uint8_t		method;

	sl_socks5_handshake_response() : sl_socks5_packet() {}
	sl_socks5_handshake_response(sl_methods m) : sl_socks5_packet(), method(m) { }
};

struct sl_socks5_connect_request : public sl_socks5_packet {
	uint8_t		cmd;
	uint8_t		rsv;	// reserved
	uint8_t		atyp;	// address type

	sl_socks5_connect_request():
		sl_socks5_packet(), cmd(sl_socks5cmd_connect), rsv(0) {}
};

struct sl_socks5_ipv4_request : public sl_socks5_connect_request {
	uint32_t	ip;
	uint16_t	port;

	sl_socks5_ipv4_request(uint32_t ipv4, uint16_t p):
		sl_socks5_connect_request(), ip(ipv4), port(p) {
		atyp = sl_socks5atyp_ipv4;
		}
};

struct sl_socks5_connect_response : public sl_socks5_packet {
	uint8_t		rep;
	uint8_t		rsv;
	uint8_t		atyp;

	sl_socks5_connect_response() : sl_socks5_packet() {}
};

struct sl_socks5_ipv4_response : public sl_socks5_connect_response {
	uint32_t	ip;
	uint16_t	port;

	sl_socks5_ipv4_response(): sl_socks5_connect_response() {}
	sl_socks5_ipv4_response(uint32_t addr, uint16_t p):
		sl_socks5_connect_response(), 
		ip(addr),
		port(p)
	{
	rep = sl_socks5rep_successed;
	atyp = sl_socks5atyp_ipv4;
	}
};
#pragma pack(pop)

// The function point to auth a connection by username and password
//typedef bool (*sl_auth_method)(const string&, const string&);
using sl_auth_method = function<bool(const string &, const string &)>;

// Setup the supported methods, can be invoke multiple times
void sl_socks5_set_supported_method(sl_methods m);

// Hand shake the new connection, if return nomethod, than should close the connection
sl_methods sl_socks5_handshake_handler(const string &req_pkt, string &resp_pkt);

// Auth the connection by username and password
bool sl_socks5_auth_by_username(const string &req_pkt, string &resp_pkt, sl_auth_method auth);

// Try to get the connection info
bool sl_socks5_get_connect_info(const string &req_pkt, string &addr, uint16_t& port);

// Failed to connect to peer
void sl_socks5_generate_failed_connect_to_peer(sl_socks5rep rep, string &resp_pkt);

// After connect to peer, send a response to the incoming connection
void sl_socks5_generate_did_connect_to_peer(const sl_peerinfo &peer, string &resp_pkt);

#endif // socklite.socks5.h

// inc/raw.h
#ifndef __SOCK_LITE_RAW_H__
#define __SOCK_LITE_RAW_H__


// Async to get the dns resolve result
typedef std::function<void(const vector<sl_ip> &)>      async_dns_handler;

/*!
    Try to get the dns result async
    @Description
    Use async udp/tcp socket to send a dns query request to the domain name server.
    If has multiple nameserver set in the system, will try all the sever in order
    till the first have a no-error response.
    The method will use a UDP socket at first, if the answer is a TC package, then
    force to send TCP request to the same server again.
    If the server does not response after timeout(5s), will try to use the next
    server in the list.
    If all server failed to answer the query, then will return 255.255.255.255 
    as the IP address of the host to query in the result.

    This method will always return an IP address.
*/
void sl_async_gethostname(const string& host, async_dns_handler fp);

/*
    Try to get the dns result async via specified name servers
*/
void sl_async_gethostname(
    const string& host, 
    const vector<sl_peerinfo>& nameserver_list, 
    async_dns_handler fp
);

/*
    Try to get the dns result via specified name servers through a socks5 proxy.
    THis will force to use tcp connection to the nameserver
*/
void sl_async_gethostname(
    const string& host, 
    const vector<sl_peerinfo>& nameserver_list, 
    const sl_peerinfo &socks5, 
    async_dns_handler fp
);

// Async to redirect the dns query request.
typedef std::function<void(const sl_dns_packet&)>       async_dns_redirector;

/*!
    Redirect a dns query packet to the specified nameserver, and return the 
    dns response packet from the server.
    If specified the socks5 proxy, will force to use tcp redirect.
*/
void sl_async_redirect_dns_query(
    const sl_dns_packet & dpkt,
    const sl_peerinfo &nameserver,
    const sl_peerinfo &socks5,
    bool force_tcp,
    async_dns_redirector fp
);

/*
    Bind Default Failed Handler for a Socket

    @Description
    Bind the default handler for SL_EVENT_FAILED of a socket.
    In any case if the socket receive a SL_EVENT_FAILED event, will
    invoke this handler.
    Wether set this handler or not, system will close the socket
    automatically. Which means, if you receive a SL_EVENT_FAILED
    event, the socket assigned in the sl_event structure has
    already been closed.
*/
void sl_socket_bind_event_failed(SOCKET_T so, sl_socket_event_handler handler);

/*
    Bind Default TimedOut Handler for a Socket

    @Description
    Bind the default timedout handler for SL_EVENT_TIMEOUT of a socket.
    If a socket receive a timedout event, the system will invoke this
    handler.
    If not bind this handler, system will close the socket automatically,
    otherwise, a timedout socket will NOT be closed.
*/
void sl_socket_bind_event_timeout(SOCKET_T so, sl_socket_event_handler handler);

/*!
    Close the socket and release the handler set 

    @Description
    This method will close the socket(udp or tcp) and release all cache/buffer
    associalate with it.
*/
void sl_socket_close(SOCKET_T so);

/*
    Monitor the socket for incoming data.

    @Description
    As reading action will block current thread if there is no data right now,
    this method will add an EPOLLIN(Linux)/EVFILT_READ(BSD) event to the queue.

    In Linux, as epoll will combine read and write flag in one set, this method
    will always monitor both EPOLLIN and EPOLLOUT.
    For a BSD based system use kqueue, will only add a EVFILT_READ to the queue.
*/
void sl_socket_monitor(
    SOCKET_T tso, 
    uint32_t timedout,
    sl_socket_event_handler callback
);

/*
    Async connect to the host via a socks5 proxy

    @Description
    Connect to host:port via a socks5 proxy.
    If the socks5 proxy is not set(like sl_peerinfo::nan()), will try to
    connect to the host in directly connection.
    If the host is not an sl_ip, then will invoke <sl_async_gethostname>
    to resolve the host first.

    If the host is connected syncized, this method will add a SL_EVENT_CONNECT
    to the events runloop and the caller will be noticed at the next
    timepiece.

    The default timeout time is 30 seconds(30000ms).
*/
void sl_tcp_socket_connect(
    const sl_peerinfo& socks5, 
    const string& host, 
    uint16_t port,
    uint32_t timedout,
    sl_socket_event_handler callback
);

/*
    Async send a packet to the peer via current socket.

    @Description
    This method will append the packet to the write queue of the socket,
    then check if current socket is writing or not.
    If is now writing, the method will return directly. Otherwise,
    this method will make the socket to monitor SL_EVENT_WRITE.

    In Linux, this method will always monitor both EPOLLIN and EPOLLOUT
*/
void sl_tcp_socket_send(
    SOCKET_T tso, 
    const string &pkt, 
    sl_socket_event_handler callback = NULL
);

/*
    Read incoming data from the socket.

    @Description
    This is a block method to read data from the socket.
    
    The socket must be NON_BLOCKING. This method will use a loop
    to fetch all data on the socket till two conditions:
    1. the buffer is not full after current recv action
    2. receive a EAGAIN or EWOULDBLOCK signal

    The method will increase the buffer's size after each loop 
    until reach the max size of string, which should be the size
    of machine memory in default.
*/
bool sl_tcp_socket_read(
    SOCKET_T tso, 
    string& buffer, 
    size_t min_buffer_size = 1024   // 1K
);

/*
    Listen on a tcp port

    @Description
    Listen on a specified tcp port on sepcified interface.
    The bind_port is the listen port info of the method.
    If you want to listen on port 4040 on all interface, set 
    <bind_port> as "0.0.0.0:4040" or sl_peerinfo(INADDR_ANY, 4040).
    If you want to listen only the internal network, like 192.168.1.0/24
    set the <bind_port> like "192.168.1.1:4040"

    The accept callback will return a new incoming socket, which
    has not been monited on any event.
*/
SOCKET_T sl_tcp_socket_listen(
    const sl_peerinfo& bind_port, 
    sl_socket_event_handler accept_callback
);

/*
    Get original peer info of a socket.

    @Description
    This method will return the original connect peerinfo of a socket
    in Linux with iptables redirect by fetch the info with SO_ORIGINAL_DST
    flag.

    In a BSD(like Mac OS X), will return 0.0.0.0:0
*/
sl_peerinfo sl_tcp_get_original_dest(SOCKET_T tso);

/*
    Redirect a socket's data to another peer via socks5 proxy.

    @Description
    This method will continuously redirect the data between from_so and the 
    peer side socket. 
    When one side close or drop the connection, this method will close
    both side's sockets.
*/
void sl_tcp_socket_redirect(
    SOCKET_T from_so,
    const sl_peerinfo& peer,
    const sl_peerinfo& socks5
);

// UDP Methods

/*
    Initialize a UDP socket

    @Description
    This method will create a UDP socket and bind to the <bind_addr>
    The ipaddress in bind_addr should always be INADDR_ANY.

    As the UDP socket is connectionless, if you want to receive any
    data on specified port, you must set the port at this time.

    In order to get the local infomation of the udp socket,
    the method will bind port 0 to this socket in default.
*/
SOCKET_T sl_udp_socket_init(
    const sl_peerinfo& bind_addr = sl_peerinfo::nan(),
    sl_socket_event_handler failed = NULL, 
    sl_socket_event_handler timedout = NULL
);

/*
    Send packet to the peer.

    @Description
    This method is an async send method.
    It will push the packet to the end of the write queue and 
    try to monitor the SL_EVENT_WRITE flag of the socket.
*/
void sl_udp_socket_send(
    SOCKET_T uso,
    const sl_peerinfo& peer,
    const string &pkt,
    sl_socket_event_handler callback = NULL
);

/*
    Listen on a UDP port and wait for any incoming data.

    @Description
    As a UDP socket is connectionless, the only different between
    listen and monitor is 'listen' will auto re-monitor the socket
    after a data incoming message has been processed.
*/
void sl_udp_socket_listen(
    SOCKET_T uso, 
    sl_socket_event_handler accept_callback
);

/*
    Block and read data from the UDP socket.

    @Description
    Same as tcp socket read method.
*/
bool sl_udp_socket_read(
    SOCKET_T uso, 
    struct sockaddr_in addr, 
    string& buffer, 
    size_t min_buffer_size = 512
);

#endif 

// sock.lite.h

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
// End of amalgamate file
