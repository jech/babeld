PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

PROGS = show_babel_packing

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

INCLUDES = babeld.h net.h kernel.c util.h interface.h source.h neighbour.h \
       route.h xroute.h message.h resend.h configuration.h local.h \
       disambiguation.h rule.h version.h

INCLUDES1 := $(INCLUDES:%=../%)

show_babel_packing: show_babel_packing.c $(INCLUDES1)
	$(CC) $(CFLAGS) $(LDFLAGS) -I.. $@.c -o show_babel_packing $(OBJS) $(LDLIBS)

clean:
	-rm -f $(PROGS) show_babel_packing.o
