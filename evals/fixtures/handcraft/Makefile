CC ?= gcc
CFLAGS ?= -O0 -g

all: libcutil.so

libcutil.so: src/c_util.c include/c_util.h
	$(CC) $(CFLAGS) -fPIC -shared -Iinclude -o $@ src/c_util.c

clean:
	rm -f libcutil.so

.PHONY: all clean
