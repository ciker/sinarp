test:test.c show.c
	gcc -fPIC -g -shared show.c -o a.so
	gcc -ldl -g -fPIC -rdynamic  test.c  -o test
	mv test ../bin/
	mv a.so ../bin/

