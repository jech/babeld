PREFIX = /usr/local

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

SRCS = babel.c net.c kernel.c util.c source.c neighbour.c \
       route.c xroute.c message.c

OBJS = babel.o net.o kernel.o util.o source.o neighbour.o \
       route.o xroute.o message.o

babel: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o babel $(OBJS) $(LDLIBS)

babel.html: babel.man
	groff -man -Thtml babel.man > babel.html

.PHONY: all install uninstall clean

all: babel

install: babel babel.man
	-rm -f $(TARGET)$(PREFIX)/bin/babel
	cp -f babel $(TARGET)$(PREFIX)/bin
	mkdir -p $(TARGET)$(PREFIX)/man/man8
	cp -f babel.man $(TARGET)$(PREFIX)/man/man8/babel.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/babel
	-rm -f $(TARGET)$(PREFIX)/man/man8/babel.8

clean:
	-rm -f babel babel.html *.o *~ core TAGS gmon.out

kernel.o: kernel_netlink.c