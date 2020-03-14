CC = gcc
FLAGS = -lssl -lcrypto
FORMAT = astyle


all: main.c
	$(CC) -I./include/ -o out *.c ./util/*.c $(FLAGS)

format:
	astyle ./*.c 
	astyle ./util/*.c
	astyle ./include/*.h

clean:
	rm ./*.orig ./include/*.orig ./util/*.orig
