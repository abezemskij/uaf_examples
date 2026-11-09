CC     = gcc
CFLAGS = -g -O0 -no-pie -fno-pic

# Pin the parameter and the fake heap to fixed virtual addresses so every
# build — on any toolchain — lays them out identically and the README
# transcripts stay correct. Round numbers chosen on purpose:
#   parameter -> 0x4a0000, heap/pool -> 0x4b0000
PARAM_ADDR = 0x4a0000
HEAP_ADDR  = 0x4b0000
PIN_PARAM  = -Wl,--section-start=.uaf_param=$(PARAM_ADDR)
PIN_HEAP   = -Wl,--section-start=.uaf_heap=$(HEAP_ADDR)

all: uaf1 reuse desk tcache groom handler

uaf1: 01_basic_uaf.c
	$(CC) $(CFLAGS) -o uaf1 01_basic_uaf.c

reuse: 02_heap_reuse.c
	$(CC) $(CFLAGS) -o reuse 02_heap_reuse.c

desk: 03_uaf_game.c
	$(CC) $(CFLAGS) $(PIN_PARAM) $(PIN_HEAP) -o desk 03_uaf_game.c

tcache: 04_bonus_glibc_tcache.c
	$(CC) $(CFLAGS) $(PIN_PARAM) -o tcache 04_bonus_glibc_tcache.c

groom: 05_heap_grooming.c
	$(CC) $(CFLAGS) $(PIN_PARAM) $(PIN_HEAP) -o groom 05_heap_grooming.c

handler: 06_uaf_handler.c
	$(CC) $(CFLAGS) $(PIN_PARAM) $(PIN_HEAP) -o handler 06_uaf_handler.c

clean:
	rm -f uaf1 reuse desk tcache groom handler

.PHONY: all clean
