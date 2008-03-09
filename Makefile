PREFIX = /usr/local

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

SRCS = babel.c net.c kernel.c util.c network.c source.c neighbour.c \
       route.c xroute.c message.c request.c filter.c

OBJS = babel.o net.o kernel.o util.o network.o source.o neighbour.o \
       route.o xroute.o message.o request.o filter.o

babel: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o babel $(OBJS) $(LDLIBS)

babel.html: babel.man
	rman -f html babel.man > babel.html

.PHONY: all install uninstall clean

all: babel babel.man

install: all
	-rm -f $(TARGET)$(PREFIX)/bin/babel
	mkdir -p $(TARGET)$(PREFIX)/bin
	cp -f babel $(TARGET)$(PREFIX)/bin
	mkdir -p $(TARGET)$(PREFIX)/man/man8
	cp -f babel.man $(TARGET)$(PREFIX)/man/man8/babel.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/babel
	-rm -f $(TARGET)$(PREFIX)/man/man8/babel.8

clean:
	-rm -f babel babel.html *.o *~ core TAGS gmon.out

kernel.o: kernel_netlink.c kernel_socket.c
