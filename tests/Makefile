# Makefile for PAM LDAP TOTP unit tests

CC = gcc
CFLAGS = -Wall -Wextra -g -I../include
LDFLAGS = -lldap -loath -lpam

# Source files from parent directory
SRC_DIR = ../src
SOURCES = $(SRC_DIR)/config.c $(SRC_DIR)/totp_validate.c $(SRC_DIR)/security_utils.c

# Object files
OBJECTS = config.o totp_validate.o security_utils.o

# Test executables
TESTS = test_config test_totp test_extract

.PHONY: all clean run

all: $(TESTS)

# Compile source files
config.o: $(SRC_DIR)/config.c
	$(CC) $(CFLAGS) -c $< -o $@

totp_validate.o: $(SRC_DIR)/totp_validate.c
	$(CC) $(CFLAGS) -c $< -o $@

security_utils.o: $(SRC_DIR)/security_utils.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build test executables
test_config: test_config.c config.o security_utils.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_totp: test_totp.c totp_validate.o security_utils.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_extract: test_extract.c
	$(CC) $(CFLAGS) $< -o $@

# Run all tests
run: all
	@echo "========================================="
	@echo "Running PAM LDAP TOTP Unit Tests"
	@echo "========================================="
	@echo ""
	@./test_config
	@echo ""
	@./test_totp
	@echo ""
	@./test_extract
	@echo ""
	@echo "========================================="
	@echo "All test suites completed!"
	@echo "========================================="

# Clean build artifacts
clean:
	rm -f $(TESTS) $(OBJECTS)
	rm -f /tmp/pam_ldap_totp_test_*
