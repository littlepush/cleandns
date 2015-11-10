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

#ifndef __CPP_UTILITY_BASE64_H__
#define __CPP_UTILITY_BASE64_H__

#include <cstdint>
#include <iostream>
#include <string>

namespace cpputility {

    /*!
    Encode a string in base64
    */
    int base64_encode( const char* istr, uint32_t len, char * ostr, uint32_t olen );
    /*!
    Encode a string object, and output to a string
    */
    int base64_encode( const std::string & istr, std::string &ostr );

    /*!
    Decode a baseed64 string
    */
    int base64_decode( const char *istr, uint32_t len, char *ostr, uint32_t blen );
    /*!
    Decode a string object, and output to a string object
    */
    int base64_decode( const std::string & istr, std::string &ostr );
}

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
