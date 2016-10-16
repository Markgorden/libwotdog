##################################
# 
# Authors: ZhangXuelian
# 	
# 
# Changes:
# 	
#	
##################################
ifeq ($(PLATFORM),UBUNTU64)
	CROSS_COMPILE=
	CC=$(CROSS_COMPILE)gcc
	CXX=$(CROSS_COMPILE)g++
	AR=$(CROSS_COMPILE)ar
	RANLIB= $(CROSS_COOMPILE)ranlib
	STRIP=$(CROSS_COMPILE)strip
	HOME=$(shell pwd)
	export HOME
	INC = -I. -I$(HOME)/include 
	CFLAGS = $(INC) -I. -I../include -finline-functions -D__LINUX_FILE__ -DHAVE_EPOLL -O3 -fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -D_GNU_SOURCE -msoft-float
	MYLIB = ../lib
	LDFLAGS = -L. -L$(MYLIB) -L../lib
endif

ifeq ($(PLATFORM),UBUNTU32)
	CROSS_COMPILE=
	CC=$(CROSS_COMPILE)gcc
	CXX=$(CROSS_COMPILE)g++
	AR=$(CROSS_COMPILE)ar
	RANLIB= $(CROSS_COoMPILE)ranlib
	STRIP=$(CROSS_COMPILE)strip
	HOME=$(shell pwd)
	export HOME
	INC = -I. -I$(HOME)/include 
	CFLAGS = $(INC) -I. -I../include -finline-functions -D__LINUX_FILE__ -DHAVE_EPOLL -O3 -fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -D_GNU_SOURCE -msoft-float
	MYLIB = $(HOME)/lib
	LDFLAGS = -L. -L$(MYLIB) -L../lib
endif	

ifeq ($(PLATFORM),CENTOS64)
	CROSS_COMPILE=
	CC=$(CROSS_COMPILE)gcc
	CXX=$(CROSS_COMPILE)g++
	AR=$(CROSS_COMPILE)ar
	RANLIB= $(CROSS_COoMPILE)ranlib
	STRIP=$(CROSS_COMPILE)strip
	HOME=$(shell pwd)
	export HOME
	INC = -I. -I$(HOME)/include 
	CFLAGS = $(INC) -I. -I../include -finline-functions -D__LINUX_FILE__ -DHAVE_EPOLL -O3 -fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -D_GNU_SOURCE -msoft-float
	MYLIB = $(HOME)/lib
	LDFLAGS = -L. -L$(MYLIB) -L../lib
endif

ifeq ($(PLATFORM),CENTOS32)
	CROSS_COMPILE=
	CC=$(CROSS_COMPILE)gcc
	CXX=$(CROSS_COMPILE)g++
	AR=$(CROSS_COMPILE)ar
	RANLIB= $(CROSS_COoMPILE)ranlib
	STRIP=$(CROSS_COMPILE)strip
	HOME=$(shell pwd)
	export HOME
	INC = -I. -I$(HOME)/include 
	CFLAGS = $(INC) -I. -I../include -finline-functions -D__LINUX_FILE__ -DHAVE_EPOLL -O3 -fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -D_GNU_SOURCE -msoft-float
	MYLIB = $(HOME)/lib
	LDFLAGS = -L. -L$(MYLIB) -L../lib
endif

ifeq ($(RELEASE),y)
	CFLAGS += -O3
else
	CFLAGS += -DDEBUG
endif

ifneq ($(NOSSL),y)
CFLAGS += -DSUPPORT_SSL
endif
