PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

SHA2_SRCS ?= rfc6234/sha224-256.c
SHA2_CFLAGS ?= -I.

BLAKE_SRCS ?= BLAKE2/ref/blake2s-ref.c
BLAKE_CFLAGS ?= -IBLAKE2/ref

LDLIBS ?= -lrt

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES) \
         $(SHA2_CFLAGS) $(BLAKE_CFLAGS)

SRCS = babeld.c net.c kernel.c util.c interface.c source.c neighbour.c \
       route.c xroute.c message.c resend.c configuration.c local.c \
       hmac.c $(SHA2_SRCS) $(BLAKE_SRCS)

OBJS = $(SRCS:.c=.o)

babeld: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o babeld $(OBJS) $(LDLIBS)

babeld.o: babeld.c version.h

local.o: local.c version.h

kernel.o: kernel_netlink.c kernel_socket.c

version.h:
	./generate-version.sh > version.h

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
	-rm -f babeld babeld.html version.h *.o */*.o */*/*.o *~ core TAGS gmon.out
