# cleandns is free software: you can redistribute it and/or modify
# Copyright (C) 2014  Push Chen

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# You can connect me by email: littlepush@gmail.com, 
# or @me on twitter: @littlepush

CLRD_ROOT = ./
OUT_DIR = $(CLRD_ROOT)/result

CLRD_DEFINES = -DVERSION=\"$(shell ./version)\" \
			 -DTARGET=\"$(shell gcc -v 2> /dev/stdout | grep Target | cut -d ' ' -f 2)\" \
			 -I./inc \
			 -std=c++11 \
			 -DCLRD_AUTO_GENERATE_DOC
			 
THIRDPARTY = -I./3rd/jsoncpp -I./3rd/socklite -I./3rd/cpputility

ifeq "$(MAKECMDGOALS)" "release"
	DEFINES = $(CLRD_DEFINES) $(THIRDPARTY) -DCLEANDNS_RELEASE -DRELEASE
	CPPFLAGS = 
	CFLAGS = -O2 -Wall $(DEFINES) -fPIC -pthread
	CXXFLAGS = -O2 -Wall $(DEFINES) -fPIC -pthread
	CMDGOAL_DEF := $(MAKECMDGOALS)
else
	ifeq "$(MAKECMDGOALS)" "withpg"
		DEFINES = $(CLRD_DEFINES) $(THIRDPARTY) -DCLEANDNS_WITHPG -DWITHPG -DDEBUG
		CPPFLAGS = 
		CFLAGS = -g -pg -Wall $(DEFINES) -fPIC -pthread
		CXXFLAGS = -g -pg -Wall $(DEFINES) -fPIC -pthread
		CMDGOAL_DEF := $(MAKECMDGOALS)
	else
		DEFINES = $(CLRD_DEFINES) $(THIRDPARTY) -DCLEANDNS_DEBUG -DDEBUG
		CPPFLAGS =
		CFLAGS = -g -Wall $(DEFINES) -fPIC -pthread
		CXXFLAGS = -g -Wall $(DEFINES) -fPIC -pthread
		CMDGOAL_DEF := $(MAKECMDGOALS)
	endif
endif

CC	 = g++
CPP	 = g++
CXX	 = g++
AR	 = ar

CPP_FILES = $(wildcard ./src/*.cpp) 3rd/jsoncpp/jsoncpp.cpp 3rd/socklite/socketlite.cpp $(wildcard 3rd/cpputility/*.cpp)
OBJ_FILES = $(CPP_FILES:.cpp=.o)

STATIC_LIBS = 
DYNAMIC_LIBS = 
EXECUTABLE = cleandns
TEST_CASE = 
RELAY_OBJECT = upfilter

all	: PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) $(RELAY_OBJECT) AfterMake

PreProcess :
	@if test -d $(OUT_DIR); then rm -rf $(OUT_DIR); fi
	@mkdir -p $(OUT_DIR)/static
	@mkdir -p $(OUT_DIR)/dynamic
	@mkdir -p $(OUT_DIR)/bin
	@mkdir -p $(OUT_DIR)/test
	@mkdir -p $(OUT_DIR)/data
	@mkdir -p $(OUT_DIR)/conf
	@mkdir -p $(OUT_DIR)/log
	@./docgen
	@echo $(CPP_FILES)

cmdgoalError :
	@echo '***************************************************'
	@echo '******You must specified a make command goal.******'
	@echo '***************************************************'

debugclean :
	@rm -rf $(TEST_ROOT)/debug

relclean :
	@rm -rf $(TEST_ROOT)/release

pgclean : 
	@rm -rf $(TEST_ROOT)/withpg

clean :
	rm -vf src/*.o; rm -vf tools/*.o; rm -vf 3rd/jsoncpp/*.o; rm -vf 3rd/socklite/*.o; rm -vf 3rd/cpputility/*.o; rm -rf $(OUT_DIR)

install:
	@if [ -f ./result/bin/cleandns ]; then cp -v ./result/bin/cleandns /usr/bin/; else echo "please make first"; fi

AfterMake : 
	@if [ "$(MAKECMDGOALS)" == "release" ]; then rm -vf src/*.o; rm -vf 3rd/jsoncpp/*.o; rm -vf 3rd/socklite/*.o; rm -vf 3rd/cpputility/*.o; fi
	@mv -vf $(CLRD_ROOT)/cleandns $(OUT_DIR)/bin/cleandns
	@mv -vf $(CLRD_ROOT)/upfilter $(OUT_DIR)/bin/upfilter

debug : PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) $(RELAY_OBJECT) AfterMake
	@exit 0

release : PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) $(RELAY_OBJECT) AfterMake
	@exit 0

withpg : PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) $(RELAY_OBJECT) AfterMake
	@exit 0

%.o: src/%.cpp 
	$(CC) $(CXXFLAGS) -c -o $@ $<

cleandns: $(OBJ_FILES)
	$(CC) -o $@ $^ $(CXXFLAGS) -lresolv

upfilter.o: tools/upfilter.cpp
	$(CC) -o tools/upfilter.o $(CXXFLAGS)

upfilter: tools/upfilter.o 3rd/socklite/socketlite.o
	$(CC) -o upfilter tools/upfilter.o 3rd/socklite/socketlite.o $(CXXFLAGS) -lresolv

