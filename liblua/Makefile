CFLAGS = $(INC) #-fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -finline-functions -msoft-float

SYSCFLAGS=
SYSLDFLAGS=
SYSLIBS=

MYCFLAGS=
MYLDFLAGS=
MYLIBS=
MYOBJS=
MYLIB = ../lib

SYSCFLAGS=-DLUA_USE_LINUX
SYSLIBS=-Wl,-E -ldl -lreadline

CFLAGS+= -O2 -Wall -DLUA_COMPAT_ALL $(SYSCFLAGS) $(MYCFLAGS)
LDFLAGS= $(SYSLDFLAGS) $(MYLDFLAGS)
LIBS= -lm $(SYSLIBS) $(MYLIBS)

TARGET = libae_lua.a

all : lapi.o lcode.o lctype.o ldebug.o ldo.o ldump.o lfunc.o lgc.o llex.o \
	lmem.o lobject.o lopcodes.o lparser.o lstate.o lstring.o ltable.o \
	ltm.o lundump.o lvm.o lzio.o \
	lauxlib.o lbaselib.o lbitlib.o lcorolib.o ldblib.o liolib.o \
	lmathlib.o loslib.o lstrlib.o ltablib.o loadlib.o linit.o luac.o 

	$(AR) -r $(TARGET) *.o
	cp $(TARGET) $(MYLIB)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean :
	/bin/rm -f *.o
	/bin/rm -f $(TARGET)
