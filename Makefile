
PKGS    = gio-2.0 gmime-2.6

CFLAGS  = -std=c99 -O2 -Wall -pedantic -D_POSIX_C_SOURCE=200809L -DMAR_GPG_BINARY_PATH="\"`which gpg`\""
CFLAGS += `pkg-config --cflags $(PKGS)`
LDFLAGS = `pkg-config --libs-only-{L,other} $(PKGS)`
LDLIBS  = `pkg-config --libs-only-l $(PKGS)`

# comment these two lines if libmagic(3) is not available
CFLAGS += -DHAVE_LIBMAGIC
LDLIBS += -lmagic

PROGS   = mar

all: $(PROGS)
all: CFLAGS += -DNDEBUG

debug: $(PROGS)
debug: CFLAGS += -g -O0
debug: LDFLAGS += -g -O0

prof: $(PROGS)
prof: CFLAGS += -pg -DNDEBUG
prof: LDFLAGS += -pg

mar.o: mar.c $(wildcard *.h)

clean:
	rm -f $(PROGS) *.o

.PHONY: all debug prof clean
