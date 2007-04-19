PREFIX = /usr/local

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

SRCS = ariadne.c net.c kernel.c util.c destination.c neighbour.c \
       route.c xroute.c message.c

OBJS = ariadne.o net.o kernel.o util.o destination.o neighbour.o \
       route.o xroute.o message.o

ariadne: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ariadne $(OBJS) $(LDLIBS)

ariadne.html: ariadne.man
	groff -man -Thtml ariadne.man > ariadne.html

.PHONY: all install uninstall clean

all: ariadne

install: ariadne ariadne.man
	-rm -f $(TARGET)$(PREFIX)/bin/ariadne
	cp -f ariadne $(TARGET)$(PREFIX)/bin
	mkdir -p $(TARGET)$(PREFIX)/man/man8
	cp -f ariadne.man $(TARGET)$(PREFIX)/man/man8/ariadne.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/ariadne
	-rm -f $(TARGET)$(PREFIX)/man/man8/ariadne.8

clean:
	-rm -f ariadne ariadne.html *.o *~ core TAGS gmon.out
