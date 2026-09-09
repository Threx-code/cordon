# An ordinary build. Compiles, tests, installs. Nothing reaches the network and
# nothing outlives the build.

PREFIX ?= /usr/local
CFLAGS ?= -O2 -Wall

.PHONY: all test install clean

all: app

app: main.c
	gcc $(CFLAGS) -o app main.c

test: app
	./app --self-test

install: app
	install -m 0755 app $(PREFIX)/bin/app

clean:
	rm -f app
