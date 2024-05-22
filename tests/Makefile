.PHONY=clean

CFLAGS = -Os -g -Wall -DTESTING

main: main.c test_utilities.o
	$(CC) $(CFLAGS) -o main main.c test_utilities.o

test_utilities.o: test_utilities.h test_utilities.c
	$(CC) $(CFLAGS) -c test_utilities.c

clean:
	rm -f main *.o
