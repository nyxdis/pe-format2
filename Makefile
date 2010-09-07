all: pe-exec
pe-exec: pe-exec.c

clean:
	rm -f pe-exec

ginstall: pe-exec
	dobin pe-exec
	dosbin pe-format2-conf.sh
	newconfd pe-format.conf $(PN)
	newinitd pe-format.init $(PN)

.PHONY: all clean ginstall
