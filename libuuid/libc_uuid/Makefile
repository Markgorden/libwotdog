CC = gcc
AR = ar

MYLIB = ../../lib

TARGET = libc_uuid.a

all : get_uuid.o

	$(AR) -r $(TARGET) *.o
	cp $(TARGET) $(MYLIB)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean :
	/bin/rm -f *.o
	/bin/rm -f $(TARGET)
