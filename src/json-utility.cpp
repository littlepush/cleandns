/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : json-utility.cpp
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

#include "json-utility.h"

// Json Utility
const Json::Value& check_key_and_get_value(const Json::Value& node, const string &key) {
    if ( node.isMember(key) == false ) {
        ostringstream _oss;
        _oss << "missing \"" << key << "\"" << endl;
        Json::FastWriter _jsonWriter;
        _oss << "check on config node: " << _jsonWriter.write(node) << endl;
        throw( runtime_error(_oss.str()) );
    }
    return node[key];
}

const Json::Value& check_key_mustbe_array(
    const Json::Value& node, 
    const string &key ) {
    bool _is_type = node[key].isArray();
    if ( !_is_type ) {
        ostringstream _oss;
        _oss << "checking array for key: \"" << key << "\" failed." << endl;
        Json::FastWriter _jsonWriter;
        _oss << "node is: " << _jsonWriter.write(node) << endl;
        throw( runtime_error(_oss.str()) );
    }
    return node[key];
}

const Json::Value& check_key_with_default(
    const Json::Value& node, 
    const string &key, 
    const Json::Value &defaultValue) {
    if ( node.isMember(key) == false ) return defaultValue;
    return node[key];
}

void check_json_value_mustby_object(const Json::Value &node) {
    if ( node.isObject() ) return;
    ostringstream _oss;
    Json::FastWriter _jsonWriter;
    _oss << "checking object for node: " << endl << "\t" <<
        _jsonWriter.write(node) << endl << "\033[1;31mFailed\033[0m" << endl;
    throw( runtime_error(_oss.str()) );
}

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */
