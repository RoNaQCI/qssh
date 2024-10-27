# Makefile for compiling qkd_gssapi.c into libgss_qkd.so

# Compiler and flags
CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g -I/usr/include/gssapi
LDFLAGS = -shared -lcurl

# Source and target files
SRC = qkd_gssapi.c
LIB = libgss_qkd.so

# Default target
all: $(LIB)

# Build the shared library
$(LIB): $(SRC)
	$(CC) $(CFLAGS) -o $(LIB) $(SRC) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f $(LIB)

