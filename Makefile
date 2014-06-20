# Make Plib Test Solution.
# Powered By Push Chen
# 
#

CLEANDNS_ROOT = ./
OUT_DIR = $(CLEANDNS_ROOT)/result

CLEANDNS_DEFINES = -DVERSION=\"$(shell ./version)\" -DTARGET=\"$(shell gcc -v 2> /dev/stdout | grep Target | cut -d ' ' -f 2)\"
THIRDPARTY = -I./inc -pthread

ifeq "$(MAKECMDGOALS)" "release"
	DEFINES = $(CLEANDNS_DEFINES) $(THIRDPARTY) -DCLEANDNS_RELEASE -DRELEASE
	CPPFLAGS = 
	CFLAGS = -O2 -Wall $(DEFINES) -fPIC -pthread
	CXXFLAGS = -O2 -Wall $(DEFINES) -fPIC -pthread
	CMDGOAL_DEF := $(MAKECMDGOALS)
else
	ifeq "$(MAKECMDGOALS)" "withpg"
		DEFINES = $(CLEANDNS_DEFINES) $(THIRDPARTY) -DCLEAN_WITHPG -DWITHPG -DDEBUG
		CPPFLAGS = 
		CFLAGS = -g -pg -Wall $(DEFINES) -fPIC -pthread
		CXXFLAGS = -g -pg -Wall $(DEFINES) -fPIC -pthread
		CMDGOAL_DEF := $(MAKECMDGOALS)
	else
		DEFINES = $(CLEANDNS_DEFINES) $(THIRDPARTY) -DCLEAN_DEBUG -DDEBUG
		CPPFLAGS =
		CFLAGS = -g -Wall $(DEFINES) -fPIC -pthread
		CXXFLAGS = -g -Wall $(DEFINES) -fPIC -pthread
		CMDGOAL_DEF := $(MAKECMDGOALS)
	endif
endif

vpath %.h   ./inc/
vpath %.cpp	./src/

CC	 = g++
CPP	 = g++
CXX	 = g++
AR	 = ar

CPP_FILES = $(wildcard ./src/*.cpp)
OBJ_FILES = $(CPP_FILES:.cpp=.o)

STATIC_LIBS = 
DYNAMIC_LIBS = 
EXECUTABLE = cleandns
TEST_CASE = 
RELAY_OBJECT = 

all	: PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) AfterMake

PreProcess :
	@if test -d $(OUT_DIR); then rm -rf $(OUT_DIR); fi
	@mkdir -p $(OUT_DIR)/static
	@mkdir -p $(OUT_DIR)/dynamic
	@mkdir -p $(OUT_DIR)/bin
	@mkdir -p $(OUT_DIR)/test
	@mkdir -p $(OUT_DIR)/data
	@mkdir -p $(OUT_DIR)/conf
	@mkdir -p $(OUT_DIR)/log
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
	rm -vf src/*.o; rm -rf $(OUT_DIR)

AfterMake : 
	rm -vf src/*.o;
	mv -vf $(CLEANDNS_ROOT)/cleandns $(OUT_DIR)/bin/cleandns

debug : PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) AfterMake
	@exit 0

release : PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) AfterMake
	@exit 0

withpg : PreProcess $(STATIC_LIBS) $(DYNAMIC_LIBS) $(EXECUTABLE) $(TEST_CASE) AfterMake
	@exit 0

%.o: src/%.cpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

cleandns : $(OBJ_FILES)
	$(CC) -o $@ $^ -pthread

