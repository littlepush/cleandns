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

}

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
