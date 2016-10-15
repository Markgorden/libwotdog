include ../config.mk
include ../server.mk

TARGET = libg_crypt.a

all : crypt.o crypt_stub.o des.o hashmd5.o md5.o SSLKernelItem.o

	$(AR) -r $(TARGET) *.o
	cp $(TARGET) $(MYLIB)
ifeq ($(PLATFORM),UBUNTU64)
	cp ./libssl64.a $(MYLIB)/libssl.a
	cp ./libcrypto64.a $(MYLIB)/libcrypto.a
endif
ifeq ($(PLATFORM),CENTOS64)
	cp ./libssl64.a $(MYLIB)/libssl.a
	cp ./libcrypto64.a $(MYLIB)/libcrypto.a
endif
ifeq ($(PLATFORM),UBUNTU32)
	cp ./libssl32.a $(MYLIB)/libssl.a
	cp ./libcrypto32.a $(MYLIB)/libcrypto.a
endif
ifeq ($(PLATFORM),CENTOS32)
	cp ./libssl32.a $(MYLIB)/libssl.a
	cp ./libcrypto32.a $(MYLIB)/libcrypto.a
endif

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean :
	/bin/rm -f *.o
	/bin/rm -f $(TARGET)
