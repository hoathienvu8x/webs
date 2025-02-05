ifeq ($(build),release)
	CFLAGS = -O3
else
	CFLAGS = -Og -g
endif
CONST =
ifeq ($(utf8check),yes)
	CONST += -DVALIDATE_UTF8=1
endif
CFLAGS += -Wall -Wextra -Wpedantic -Wno-overlength-strings -Wno-strict-aliasing
STD := c89
CC := gcc

all: compile build

compile:
	@echo "build options:"
	@echo "CFLAGS = ${CFLAGS}"
	@echo "STD    = ${STD}"
	@echo "CC     = ${CC}"
	@echo
	
	$(CC) -c *.c examples/test.c $(CFLAGS) -std=$(STD) $(CONST)

build: compile
	$(CC) -o webs *.o -lpthread -lm $(CONST)

clean:
	-rm -f webs 
	-rm -f *.o
