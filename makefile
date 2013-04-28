debug:sinarp.c sinarp.h
	gcc -ldl -lm -Wall -g -DDEBUG -fPIC -lpthread -rdynamic  -I./WpdPack/Include/ sinarp.c -o sinarp
release:sinarp.c sinarp.c
	gcc -ldl -lm -o2  -fPIC -lpthread -rdynamic  -I./WpdPack/Include/ sinarp.c -o sinarp
clean:
	rm sinarp
