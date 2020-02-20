PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

CDEBUGFLAGS = -Os -g -Wall -Wextra -Wvla -Wno-unused-parameter

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = -I. $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

LDLIBS = -lrt

SRCS = babeld.c net.c kernel.c util.c interface.c source.c neighbour.c \
       route.c xroute.c message.c resend.c configuration.c local.c \
       disambiguation.c rule.c

OBJS = $(SRCS:%.c=%.o)

babeld: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

babeld.o: babeld.c version.h

local.o: local.c version.h

kernel.o: kernel_netlink.c kernel_socket.c

version.h:
	./$(VPATH)/generate-version.sh > $@

.SUFFIXES: .c .o
.c.o:
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

.SUFFIXES: .man .html

.man.html:
	mandoc -Thtml $< > $@

babeld.html: babeld.man

.PHONY: all install install.minimal uninstall clean

all: babeld babeld.man

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
	-rm -f babeld babeld.html version.h *.o *~ core TAGS gmon.out
