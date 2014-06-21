/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : config.h
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

#ifndef __CLEAN_DNS_CONFIG_H__
#define __CLEAN_DNS_CONFIG_H__

// COMMON System Check Macro Definiton.
// The following code pieces are in <https://github.com/PushLab/plib>
// I just copy this code to check the system & platform.
#if ( defined WIN32 | defined _WIN32 | defined WIN64 | defined _WIN64 )
    #define _PLIB_PLATFORM_WIN      1
#elif TARGET_OS_WIN32
    #define _PLIB_PLATFORM_WIN      1
#elif defined __CYGWIN__
    #define _PLIB_PLATFORM_WIN      1
#else
    #define _PLIB_PLATFORM_WIN      0
#endif
#ifdef __APPLE__
    #define _PLIB_PLATFORM_MAC      1
#else
    #define _PLIB_PLATFORM_MAC      0
#endif
#if _PLIB_PLATFORM_WIN == 0 && _PLIB_PLATFORM_MAC == 0
    #define _PLIB_PLATFORM_LINUX    1
#else
    #define _PLIB_PLATFORM_LINUX    0
#endif
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    #define _PLIB_PLATFORM_IOS      1
#else
    #define _PLIB_PLATFORM_IOS      0
#endif

#define _DEF_WIN32  (_PLIB_PLATFORM_WIN == 1)
#define _DEF_LINUX  (_PLIB_PLATFORM_LINUX == 1)
#define _DEF_MAC    (_PLIB_PLATFORM_MAC == 1)
#define _DEF_IOS    (_PLIB_PLATFORM_IOS == 1)

#if _DEF_WIN32
// Disable the certain warn in Visual Studio for old functions.
#pragma warning (disable : 4996)
#pragma warning (disable : 4251)

#endif

// Usable C Header files including.
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
// Usable CPP Header files
#include <locale>
#include <iostream>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <algorithm>

// Socket Including file in Windows must in a specified order.
#if _DEF_WIN32
#include <WinSock2.h>
#include <Windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <stddef.h>
#include <sys/time.h>
#endif

// Linux Thread, pit_t
#if _DEF_LINUX
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

#ifndef __UNICODE
#define UNICODE_(x)     x
#else
#define UNICODE_(x)     _T(x)
#endif

// Common Type definition
typedef signed char             Int8;
typedef signed short int        Int16;
typedef signed int              Int32;
typedef signed long long int    Int64;
typedef unsigned char           Uint8;
typedef unsigned short int      Uint16;
typedef unsigned int            Uint32;
typedef unsigned long long int  Uint64;

typedef void * Vptr;

typedef enum { False = 0, True = 1 } Boolean;

// Function and error.
#if _DEF_WIN32

  #define _PLIB_FUNC_NAME_FULL_ __FUNCSIG__
  #define _PLIB_FUNC_NAME_SIMPLE_   __FUNCTION__

  #define PLIB_LASTERROR    GetLastError()

#else

  #define _PLIB_FUNC_NAME_FULL_ __PRETTY_FUNCTION__
  #define _PLIB_FUNC_NAME_SIMPLE_ __FUNCTION__

  #define PLIB_LASTERROR    errno   

#endif

#ifdef _PLIB_FULL_FUNCNAME
  #define PLIB_FUNC_NAME    _PLIB_FUNC_NAME_FULL_
#else
  #define PLIB_FUNC_NAME    _PLIB_FUNC_NAME_SIMPLE_
#endif

// Log Basic Format: [YYYY-mm-dd HH:MM:SS,ms][ThreadId][FILE][Function][Line]
#define PLIB_TIME_FORMAT_BASIC  UNICODE_("%04d-%02d-%02d %02d:%02d:%02d,%03d")
#define PLIB_LOG_FORMAT_BASIC   UNICODE_("[%s][%u][%s][%s][%d]")
// Log Simple Format: [Time][ThreadId][FUNCTION][LINE][ThreadId]
#define PLIB_TIME_FORMAT_SIMPLE UNICODE_("%04d-%02d-%02d %02d:%02d")
#define PLIB_LOG_FORMAT_SIMPLE  UNICODE_("[%s][%u][%s][%d]")
// Log Postfix Fomat: [YYYY-mm-dd-HH-MM-SS]
#define PLIB_TIME_FORMAT_POSTFIX UNICODE_("%04d-%02d-%02d-%02d-%02d-%02d")

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

using namespace std;

#endif // cleandns.config.h

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */