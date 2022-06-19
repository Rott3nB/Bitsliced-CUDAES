CC = gcc
C_ARGS += -maes -fopenmp

all: clean test_aesni

test_aesni: main.o aesni.o
	$(CC) $(C_ARGS) -o $@ $^

main.o: main.c test_vectors.h
	$(CC) $(C_ARGS) -o $@ -c $<

aesni.o: aesni.c
	$(CC) $(C_ARGS) -o $@ -c $<

test_vectors.h: generate_test_vectors.py
	python3 $< > $@

clean:
	@rm -f *.o
	@rm -f test_vectors.h

.PHONY: clean
