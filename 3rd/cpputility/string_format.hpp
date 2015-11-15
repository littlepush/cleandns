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

#ifndef __CPP_UTILITY_STRING_FORMAT_HPP__
#define __CPP_UTILITY_STRING_FORMAT_HPP__

#include <iostream>
#include <string>
#include <vector>

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

    // Dump binary package with HEX
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

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
