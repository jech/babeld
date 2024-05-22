# NOTE: This expects that the top-level Makefile was ran with -DTESTING.

.PHONY=clean

CFLAGS = -Os -g -Wall

OBJS = ../babeld.o ../net.o ../kernel.o ../util.o ../interface.o ../source.o \
	   ../neighbour.o ../route.o ../xroute.o ../message.o ../resend.o \
	   ../configuration.o ../local.o ../hmac.o ../rfc6234/sha224-256.o \
	   ../BLAKE2/ref/blake2s-ref.o test_utilities.o util_test.o

main: main.c test_utilities.o util_test.o
	$(CC) $(CFLAGS) -o main main.c $(OBJS)

test_utilities.o: test_utilities.h test_utilities.c
	$(CC) $(CFLAGS) -c test_utilities.c

util_test.o: util_test.c util_test.h
	$(CC) $(CFLAGS) -c util_test.c

clean:
	rm -f main *.o