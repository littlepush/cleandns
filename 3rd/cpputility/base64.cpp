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

#include "base64.h"
#include <cstdint>

namespace cpputility {

    using namespace std;

    int base64_encode( const char* istr, uint32_t len, char * ostr, uint32_t olen ) {
        static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        // Invalidate input
        if ( istr == NULL || ostr == NULL || len == 0 || olen == 0 ) return -1;

        unsigned long long inputLength = (unsigned long long)len;
        const unsigned char *inputBytes = (const unsigned char *)istr;
        
        long long maxOutputLength = ((inputLength / 3) + (inputLength % 3 == 0 ? 0 : 1)) * 4;
        
        // Not enough output space
        if ( maxOutputLength > olen ) return -1;
        
        unsigned char *outputBytes = (unsigned char *)ostr;
        
        unsigned long long i;
        unsigned long long outputLength = 0;
        for (i = 0; i < inputLength - 2; i += 3)
        {
            outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
            outputBytes[outputLength++] = lookup[((inputBytes[i] & 0x03) << 4) | ((inputBytes[i + 1] & 0xF0) >> 4)];
            outputBytes[outputLength++] = lookup[((inputBytes[i + 1] & 0x0F) << 2) | ((inputBytes[i + 2] & 0xC0) >> 6)];
            outputBytes[outputLength++] = lookup[inputBytes[i + 2] & 0x3F];
        }
        
        //handle left-over data
        if (i == inputLength - 2)
        {
            // = terminator
            outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
            outputBytes[outputLength++] = lookup[((inputBytes[i] & 0x03) << 4) | ((inputBytes[i + 1] & 0xF0) >> 4)];
            outputBytes[outputLength++] = lookup[(inputBytes[i + 1] & 0x0F) << 2];
            outputBytes[outputLength++] =   '=';
        }
        else if (i == inputLength - 1)
        {
            // == terminator
            outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
            outputBytes[outputLength++] = lookup[(inputBytes[i] & 0x03) << 4];
            outputBytes[outputLength++] = '=';
            outputBytes[outputLength++] = '=';
        }
        return (int)outputLength;
    }

    int base64_encode( const string & istr, string &ostr )
    {
        ostr.resize(((istr.size() / 3) + (istr.size() % 3 == 0 ? 0 : 1)) * 4);
        int _retval = base64_encode(istr.c_str(), istr.size(), &ostr[0], ostr.size());
        if ( _retval < 0 ) return _retval;
        ostr.resize(_retval);
        return _retval;
    }

    int base64_decode( const char *istr, uint32_t len, char *ostr, uint32_t blen ) {
        static const char lookup[] =
        {
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 62, 99, 99, 99, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 99, 99, 99, 99, 99, 99,
            99,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 99, 99, 99, 99, 99,
            99, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 99, 99, 99, 99, 99
        };
        
        // Invalidate input
        if ( istr == NULL || ostr == NULL || len == 0 || blen == 0 ) return -1;
        // invalidate input string length
        if ( (len % 4) != 0 ) return -1;

        long long inputLength = len;
        const unsigned char *inputBytes = (const unsigned char *)istr;
        
        long long maxOutputLength = ((inputLength / 4) + (inputLength % 4 == 0 ? 0 : 1)) * 3;
        // Invalidate output length
        if ( maxOutputLength > blen ) return -1;
        
        unsigned char *outputBytes = (unsigned char *)ostr;
        
        int accumulator = 0;
        long long outputLength = 0;
        unsigned char accumulated[] = {0, 0, 0, 0};
        for (long long i = 0; i < inputLength; i++)
        {
            unsigned char decoded = lookup[inputBytes[i] & 0x7F];
            if (decoded != 99)
            {
                accumulated[accumulator] = decoded;
                if (accumulator == 3)
                {
                    outputBytes[outputLength++] = (accumulated[0] << 2) | (accumulated[1] >> 4);
                    outputBytes[outputLength++] = (accumulated[1] << 4) | (accumulated[2] >> 2);
                    outputBytes[outputLength++] = (accumulated[2] << 6) | accumulated[3];
                }
                accumulator = (accumulator + 1) % 4;
            }
        }
        
        //handle left-over data
        if (accumulator > 0) outputBytes[outputLength] = (accumulated[0] << 2) | (accumulated[1] >> 4);
        if (accumulator > 1) outputBytes[++outputLength] = (accumulated[1] << 4) | (accumulated[2] >> 2);
        if (accumulator > 2) outputLength++;
        
        //truncate data to match actual output length
        return (int)outputLength;
    }

    int base64_decode( const string & istr, string &ostr ) {
        ostr.resize(((istr.size() / 4) + (istr.size() % 4 == 0 ? 0 : 1)) * 3);
        int _retval = base64_decode(istr.c_str(), istr.size(), &ostr[0], ostr.size());
        if ( _retval < 0 ) return _retval;
        ostr.resize(_retval);
        return _retval;
    }
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
