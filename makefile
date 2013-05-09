SUBDIRS = fake_http_response

release:sinarp.c sinarp.c
	gcc -ldl -lm -O3  -fPIC -lpthread -rdynamic  -I./WpdPack/Include/ sinarp.c -o ./bin/sinarp
	make plugin
debug:sinarp.c sinarp.h
	gcc -ldl -lm -Wall -g -DDEBUG -fPIC -lpthread -rdynamic  -I./WpdPack/Include/ sinarp.c -o ./bin/sinarp
	make plugin
plugin: plugin/$(SUBDIRS)
	for dir in $(SUBDIRS); do \
           $(MAKE) -C plugin/$$dir; \
        done

clean:
	rm ./bin/sinarp -rf
	rm ./bin/*.so -rf
	rm ./bin/*.o -rf
	find -iregex '.*\(release\|debug\)$$' -type d -exec rm {} -rf \;
	find -iregex '.*\(\.exp\|\.dll\)$$' -type f -exec rm {} -rf \;
	
