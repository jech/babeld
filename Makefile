PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

LDLIBS = -lrt

SRCS = babeld.c net.c kernel.c util.c interface.c source.c neighbour.c \
       route.c xroute.c message.c resend.c configuration.c local.c \
       disambiguation.c rule.c

OBJS = babeld.o net.o kernel.o util.o interface.o source.o neighbour.o \
       route.o xroute.o message.o resend.o configuration.o local.o \
       disambiguation.o rule.o

INCLUDES = babeld.h net.h kernel.c util.h interface.h source.h neighbour.h \
       route.h xroute.h message.h resend.h configuration.h local.h \
       disambiguation.h rule.h version.h

babeld: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o babeld $(OBJS) $(LDLIBS)

babeld.o: babeld.c $(INCLUDES)

local.o: local.c local.h version.h babeld.h interface.h source.h neighbour.h \
	 kernel.h xroute.h route.h util.h configuration.h

kernel.o: kernel_netlink.c kernel_socket.c kernel.h babeld.h

configuration.o: configuration.c babeld.h util.h route.h kernel.h \
		 configuration.h rule.h

disambiguation.o: disambiguation.c babeld.h util.h route.h kernel.h \
		  disambiguation.h interface.h rule.h

interface.o: interface.c babeld.h util.h route.h kernel.h local.h \
	     interface.h neighbour.h message.h configuration.h xroute.h

message.o: message.c babeld.h util.h net.h interface.h source.h neighbour.h \
	   route.h kernel.h xroute.h resend.h configuration.h

neighbour.o: neighbour.c babeld.h util.h interface.h source.h route.h \
	     neighbour.h message.h resend.h local.h

net.o: net.c net.h babeld.h util.h

resend.o: resend.c babeld.h util.h neighbour.h message.h interface.h \
	  resend.h configuration.h

route.o: route.c babeld.h util.h kernel.h interface.h source.h neighbour.h \
	 route.h xroute.h message.h configuration.h local.h disambiguation.h

rule.o: rule.c babeld.h util.h kernel.h configuration.h rule.h

source.o: source.c babeld.h util.h interface.h route.h source.h

util.o: util.c babeld.h util.h

xroute.o: xroute.c babeld.h kernel.h neighbour.h message.h route.h util.h \
	  xroute.h configuration.h interface.h local.h
version.h:
	./generate-version.sh > version.h

.SUFFIXES: .man .html

.man.html:
	mandoc -Thtml $< > $@

babeld.html: babeld.man

.PHONY: all install install.minimal uninstall clean reallyclean

all: babeld babeld.man

TAGS: $(SRCS) $(INCLUDES)
	etags $(SRCS) $(INCLUDES)

tags: $(SRCS) $(INCLUDES)
	ctags $(SRCS) $(INCLUDES)

install.minimal: babeld
	-rm -f $(TARGET)$(PREFIX)/bin/babeld
	mkdir -p $(TARGET)$(PREFIX)/bin
	cp -f babeld $(TARGET)$(PREFIX)/bin

install: install.minimal all
	mkdir -p $(TARGET)$(MANDIR)/man8
	cp -f babeld.man $(TARGET)$(MANDIR)/man8/babeld.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/babeld
	-rm -f $(TARGET)$(MANDIR)/man8/babeld.8

clean:
	-rm -f babeld babeld.html version.h *.o *~ core

reallyclean: clean
	-rm -f TAGS tags gmon.out cscope.out
