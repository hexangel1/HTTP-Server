PROJECT = httpserv
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)
SPECIAL = Makefile README.md LICENSE
CSOURCE = -D _XOPEN_SOURCE=500 -D _POSIX_C_SOURCE=200809L
CDEFINE = -D BUILD_FOR_LINUX -D USE_EXCLUSIVE
CFLAGS = -Wall -g -O0 -ansi -pedantic $(CSOURCE) $(CDEFINE)
LDLIBS = -pthread 
CC = gcc
CTAGS = ctags
INSTALL = install
PREFIX = /usr/local
ARGV = -w 8 -i 127.0.0.1 -p 8080
TESTFILE = test.bin

$(PROJECT): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(LDLIBS) $(OBJECTS)

$(PROJECT).tar: $(SOURCES) $(HEADERS) $(SPECIAL)
	tar -cf $@ $(SOURCES) $(HEADERS) $(SPECIAL)

$(TESTFILE):
	dd if=/dev/random of=./$@ count=512

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

run: $(PROJECT)
	./$(PROJECT) $(ARGV)

memcheck: $(PROJECT)
	valgrind -s --leak-check=full ./$(PROJECT) $(ARGV)

systrace: $(PROJECT)
	strace -Cwf ./$(PROJECT) $(ARGV)

muxtrace: $(PROJECT)
	mutrace --all ./$(PROJECT) $(ARGV)

benchmark: $(TESTFILE)
	wrk -t12 -c400 -d10s --timeout 1s http://localhost:8080/test.bin

ping: $(TESTFILE)
	curl -I http://localhost:8080/test.bin

stop:
	pkill -SIGTERM $(PROJECT)

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

tar: $(PROJECT).tar

clean:
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags

install: $(PROJECT)
	$(INSTALL) $(PROJECT) $(PREFIX)/bin

uninstall:
	rm -f $(PREFIX)/bin/$(PROJECT)

ifneq (unistall, $(MAKECMDGOALS))
ifneq (clean, $(MAKECMDGOALS))
ifneq (stop, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
ifneq (tar, $(MAKECMDGOALS))
-include deps.mk
endif
endif
endif
endif
endif

