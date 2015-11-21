/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : json-utility.h
 * Author            : Push Chen
 * Date              : 2015-11-21
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

#ifndef __CLEAN_DNS_JSON_UTILITY_H__
#define __CLEAN_DNS_JSON_UTILITY_H__

#include <list>
#include <algorithm>

#include "json/json.h"
#include "json/json-forwards.h"

using namespace std;

// Json Utility
const Json::Value& check_key_and_get_value(const Json::Value& node, const string &key);
const Json::Value& check_key_mustbe_array(const Json::Value& node, const string &key );
const Json::Value& check_key_with_default(const Json::Value& node, const string &key, const Json::Value &defaultValue);
void check_json_value_mustby_object(const Json::Value &node);

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
