/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : cf.h
 * Author            : Push Chen
 * Date              : 2014-11-23
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

#ifndef __CLEAN_DNS_CF_H__
#define __CLEAN_DNS_CF_H__

#include <iostream>
#include <string>
#include <list>
#include <map>
#include <fstream>
#include "config.h"

using namespace std;

class config_section
{
    map<string, string> m_config_nodes;
    map<string, config_section*> m_sub_sections;
    map<string, string>::iterator m_iterator;
    string m_name;
    int m_config_level;
    bool m_config_status;

    bool _internal_process_until_find_section_header(ifstream &in, string &head_string);
    config_section();
public:

    typedef map<string, string>::iterator _tnode;

    config_section(ifstream &in);
    ~config_section();

    string &name;

    // check if the config has been loaded correctly.
    operator bool() const;

    void begin_loop();
    map<string, string>::iterator end();
    map<string, string>::iterator current_node();
    void next_node();

    string & operator[](const string &k);
    string & operator[](const char *k);
    bool contains_key(const string &k);
    void get_sub_section_names(vector<string> &names);
    config_section * sub_section(const string &name);
};

config_section* open_config_file(const char* fp);
void close_config_file(config_section* cs);

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */