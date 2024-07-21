CC = gcc
CFLAGS = -Og -g
LDFLAGS = -I. -ldl -lpthread -lm
ifeq ($(build),release)
	CFLAGS = -O3
	LDFLAGS += -DNDEBUG=1
endif
CFLAGS += -Wall -pedantic -fPIC
RM = rm -rf
SOURCES = $(filter-out tradingbot.c, $(wildcard *.c))
OBJECTS = $(addprefix objects/,$(SOURCES:.c=.o))

EXECUTABLE = tradingbot

all: objects $(SOURCES)

objects:
	mkdir -p objects

$(EXECUTABLE): objects/tradingbot.o $(OBJECTS)
	$(CC) objects/tradingbot.o $(OBJECTS) -o $@ $(LDFLAGS)

objects/%.o: %.c
	$(CC) -c -std=gnu99 $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	$(RM) objects/*.o $(EXECUTABLE)
