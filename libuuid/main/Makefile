# expects uuid-dev package (Ubuntu) or similar
CC=gcc

all: get_uuid

get_uuid: main.o
	$(CC) -o $@ $< -L../../lib -lc_uuid -lg_uuid

.PHONY: clean

clean: 
	rm -f get_uuid