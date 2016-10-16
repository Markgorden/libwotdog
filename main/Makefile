##################################
# 
# Authors: ZhangXuelian
# 	
# 
# Changes:
# 	
#	
##################################
#-------------------------------------------------
include ../config.mk
include ../server.mk

EXTRALIB += -lae_stl -lae_pthread -lae_net -lae_log -lae_protocol -lae_utility
EXTRALIB += -lpthread#-ldl -lm -lc 

ifeq ($(USE_SSL),y)
EXTRALIB += -lssl -lcrypto 
endif

#-------------------------------------------------
OBJS = server.o server_cron.o t_dict.o networking.o option.o
#-------------------------------------------------
TARGET = main
#-------------------------------------------------
all : $(TARGET)
$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(EXTRALIB)	
ifeq ($(RELEASE),y)	
	$(STRIP) $(TARGET)
endif	

.PHONY: clean

clean: 
	rm -f main
    