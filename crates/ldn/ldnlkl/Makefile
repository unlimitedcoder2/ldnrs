TARGET   ?=
CC       := clang
AR       := llvm-ar
STRIP    := $(if $(TARGET),$(TARGET)-,)strip
CFLAGS   ?= -Wall -Wextra -Wpedantic

LIBLKL := $(LKL_DIR)/tools/lkl/liblkl.a
CFLAGS += $(if $(TARGET),--target=$(TARGET)) -std=gnu23 -pthread -Iinclude -Ivendor -I$(LKL_DIR)/tools/lkl/include/mingw32 -I$(LKL_DIR)/tools/lkl/include

all: ldn-lkl.a ldn-lkl-debug.a

ldn-lkl-debug.a: lib-debug.o
	cp $(LIBLKL) $@
	$(AR) rs $@ $<

ldn-lkl.a: lib.o
	cp $(LIBLKL) $@
	$(AR) rs $@ $<
	$(STRIP) --strip-debug $@

lib.o: src/lib.c
	$(CC) $(CFLAGS) -g0 -O2 -c $< -o $@

lib-debug.o: src/lib.c
	$(CC) $(CFLAGS) -g -O0 -c $< -o $@

clean:
	rm -f ldn-lkl.a ldn-lkl-debug.a lib.o lib-debug.o

.PHONY: all clean
