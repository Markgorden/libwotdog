CC = gcc
AR = ar

MYLIB = ../../lib

TARGET = libg_uuid.a

all : clear.o \
		compare.o \
		copy.o \
		gen_uuid.o \
		isnull.o \
		pack.o \
		parse.o \
		unpack.o \
		unparse.o \
		uuid_time.o

	$(AR) -r $(TARGET) *.o
	cp $(TARGET) $(MYLIB)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean :
	/bin/rm -f *.o
	/bin/rm -f $(TARGET)
