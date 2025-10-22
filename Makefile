# Makefile for PAM LDAP TOTP module

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -I./include
LDFLAGS = -shared
LIBS = -lpam -lldap -llber -loath
TARGET = pam_ldap_totp.so
INSTALL_DIR = /lib/security

SRCDIR = src
OBJDIR = obj
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean install test check

all: $(TARGET) test

check: test

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built $(TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)
	@if [ -d tests ]; then $(MAKE) -C tests clean; fi
	@echo "Cleaned build files"

install: $(TARGET)
	install -D -m 0644 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "Installed $(TARGET) to $(INSTALL_DIR)"

test:
	@echo "Running tests..."
	@if [ -d tests ]; then \
		$(MAKE) -C tests run; \
	else \
		echo "No tests directory found"; \
	fi

# Dependencies
$(OBJDIR)/pam_ldap_totp.o: include/pam_ldap_totp.h
$(OBJDIR)/config.o: include/pam_ldap_totp.h
$(OBJDIR)/ldap_query.o: include/pam_ldap_totp.h
$(OBJDIR)/totp_validate.o: include/pam_ldap_totp.h
$(OBJDIR)/security_utils.o: include/pam_ldap_totp.h
