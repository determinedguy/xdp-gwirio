CC = gcc
CFLAGS = -Wall -O2
LIBS = -lbpf -lelf

TARGET = xdp_test

all: $(TARGET)

$(TARGET): xdp_test.c
	$(CC) $(CFLAGS) -o $(TARGET) xdp_test.c $(LIBS)

clean:
	rm -f $(TARGET)
