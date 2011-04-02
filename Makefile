CC     = gcc
CFLAGS = -Wall

libudbus.a: udbus.o
	$(AR) cr $@ $+

example: udbus.o example.o
	$(CC) $(CFLAGS) -o $@ $+

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -rf *.o *.a example
