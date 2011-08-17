CC     = gcc
CFLAGS = -Wall

libudbus.a: udbusloop.o udbus.o
	$(AR) cr $@ $+

example: udbus.o example.o
	$(CC) $(CFLAGS) -o $@ $+

example2: udbus.o example2.o
	$(CC) $(CFLAGS) -o $@ $+

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -rf *.o *.a example
