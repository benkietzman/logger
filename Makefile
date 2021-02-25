###########################################
# Logger
# -------------------------------------
# file       : Makefile
# author     : Ben Kietzman
# begin      : 2014-07-22
# copyright  : kietzman.org
# email      : ben@kietzman.org
###########################################

MAKEFLAGS="-j ${C}"
prefix=/usr/local

all: bin/logger

bin/%: ../common/libcommon.a obj/%.o
	-if [ ! -d bin ]; then mkdir bin; fi;
	g++ -o bin/logger obj/logger.o $(LDFLAGS) -L../common -lbz2 -lcommon -lb64 -lcrypto -lexpat -lmjson -lnsl -lpthread -lrt -lssl -ltar -lz

../common/libcommon.a:
	cd ../common; ./configure; make;

obj/%.o: %.cpp
	-if [ ! -d obj ]; then mkdir obj; fi;
	g++ -ggdb -Wall -c $< -o $@ $(CPPFLAGS) -I../common

install: bin/logger
	-if [ ! -d $(prefix)/logger ]; then mkdir $(prefix)/logger; fi;
	install --mode=777 bin/logger $(prefix)/logger/
	if [ ! -f /lib/systemd/system/logger.service ]; then install --mode=644 logger.service /lib/systemd/system/; fi;

clean:
	-rm -fr obj bin

uninstall:
	-rm -f $(prefix)/logger
