##################################
# 
# Authors: ZhangXuelian
# 	
# 
# Changes:
# 	
#	
##################################
subdirs = libaenet libstl libutility libpthread liblog libcrypt libuuid libprotocol #liblua
subdirs += main
HOME=$(shell pwd)
export HOME
all:
	@for dir in $(subdirs); do make -C $$dir||exit $$?; done

clean:
	@for dir in $(subdirs); do make -C $$dir clean; done
	rm -f lib/*.a
	rm -f lib/*.so

