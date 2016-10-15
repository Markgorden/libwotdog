include ../config.mk
include ../server.mk

TARGET = libae_utility.a

all : util.o zmalloc.o endianconv.o md5.o pqsort.o sds.o crc16.o crc64.o rand.o sha1.o sds.o

	$(AR) -r $(TARGET) *.o
	cp $(TARGET) $(MYLIB)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $< -I ../include

clean :
	/bin/rm -f *.o
	/bin/rm -f $(TARGET)
