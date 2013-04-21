sinarp:sinarp.c sinarp.h
	gcc -ldl -lm  -g -fPIC -lpthread -rdynamic  -I./WpdPack/Include/ sinarp.c -o sinarp
	mv sinarp bin/
