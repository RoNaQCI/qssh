# Compiler and flags
CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g -I/usr/include/gssapi
LDFLAGS = -shared -lcurl -ljson-c -lssl -lcrypto -luuid

# Source and target files
SRC = qkd_gssapi.c qkd.c
LIB = libgss_qkd.so
TEST_SRC = test_qkd.c qkd.c
TEST_BIN = test_qkd

# Default target
all: $(LIB)

# Build the shared library
$(LIB): $(SRC)
	$(CC) $(CFLAGS) -o $(LIB) $(SRC) $(LDFLAGS)

# Build the test program
$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) -lcurl -ljson-c -lssl -lcrypto -luuid


# Clean up build artifacts
clean:
	rm -f $(LIB) test_qkd
