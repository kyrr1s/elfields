CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -pedantic
TARGET = elfields
SOURCES = main.c
OBJECTS = main.o
HEADERS = main.h

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall