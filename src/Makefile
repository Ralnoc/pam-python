all:	ctest pam_python.so test-pam_python.pam

WARNINGS=-Wall -Wextra -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Werror
#WARNINGS=-Wunreachable-code 	# Gcc 4.1 .. 4.4 are too buggy to make this useful

LIBDIR ?= /lib/security

pam_python.so: pam_python.c setup.py Makefile
	@rm -f "$@"
	@[ ! -e build -o build/lib.*/$@ -nt setup.py -a build/lib.*/$@ -nt Makefile ] || rm -r build
	CFLAGS="$(WARNINGS) -I/usr/local/lib/ " ./setup.py build
	@#CFLAGS="-O0 $(WARNINGS)" ./setup.py build --debug
	@#CFLAGS="-O0 $(WARNINGS)" Py_DEBUG=1 ./setup.py build --debug
	ln -sf build/lib.*/$@ .

.PHONY: install install-lib
install: install-lib
install-lib:
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp build/lib.*/pam_python.so $(DESTDIR)$(LIBDIR)

.PHONY: clean
clean:
	rm -rf build ctest pam_python.so test-pam_python.pam test.pyc core
	[ ! -e /etc/pam.d/test-pam_python.pam ] || { s=$$([ $$(id -u) = 0 ] || echo sudo); $$s rm -f /etc/pam.d/test-pam_python.pam; }

.PHONY: ctest
ctest:	ctest.c Makefile
	gcc -O0 $(WARNINGS) -g -o $@ ctest.c -lpam

test-pam_python.pam: test-pam_python.pam.in Makefile
	sed "s,\\\$$PWD,$$(pwd),g" "$@.in" >"$@.tmp" 
	mv $@.tmp $@

/etc/pam.d/test-pam_python.pam: test-pam_python.pam
	s=$$([ $$(id -u) = 0 ] || echo sudo); $$s ln -sf $$(pwd)/test-pam_python.pam /etc/pam.d

.PHONY: test
test: pam_python.so ctest /etc/pam.d/test-pam_python.pam
	python test.py
	./ctest
