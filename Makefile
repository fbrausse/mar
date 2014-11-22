
PKGS    = gio-2.0 gmime-2.6

CFLAGS  = -std=c99 -O2 -Wall -pedantic -D_POSIX_C_SOURCE=200809L
CFLAGS += `pkg-config --cflags $(PKGS)`
LDFLAGS = `pkg-config --libs-only-{L,other} $(PKGS)`
LDLIBS  = `pkg-config --libs-only-l $(PKGS)`

PROGS   = mar

all: $(PROGS)
all: CFLAGS += -DNDEBUG

debug: $(PROGS)
debug: CFLAGS += -g -O0
debug: LDFLAGS += -g -O0

prof: $(PROGS)
prof: CFLAGS += -pg
prof: LDFLAGS += -pg

mar.o: mar.c $(wildcard *.h)

clean:
	rm -f $(PROGS) *.o

.PHONY: all debug prof clean
