CC = gcc
AR = ar

MYLIB = ../lib

TARGET = libae_pthread.a

all : thread.o

	$(AR) -r $(TARGET) *.o
	cp $(TARGET) $(MYLIB)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $< -I ../include

clean :
	/bin/rm -f *.o
	/bin/rm -f $(TARGET)
