CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
LDFLAGS = 

TARGET = main

SOURCES = main.c \
          b64/b64.c \
          der/der.c \
          der/der_strings.c \
          der/der_utils.c \
          der/der_file.c \
          pem/pem.c \
          util/util.c \
          x509/x509.c

OBJECTS = $(SOURCES:.c=.o)

HEADERS = b64/b64.h \
          der/der.h \
          der/der_utils.h \
          der/der_file.h \
          pem/pem.h \
          util/util.h \
          x509/x509.h

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

rebuild: clean all

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

run: $(TARGET)
	./$(TARGET)

run-cert: $(TARGET)
	./$(TARGET) $(CERT)

format:
	clang-format -i $(SOURCES) $(HEADERS)

.PHONY: all clean rebuild install uninstall run run-cert format