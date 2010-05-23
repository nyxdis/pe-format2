all: pe-exec
pe-exec: pe-exec.c

clean:
	rm -f pe-exec

.PHONY: all clean
