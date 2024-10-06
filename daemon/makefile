HASHMAPDIR=c-hashmap/
SOURCEDIR=src/
TESTINCLUDES=-Iinclude/
INCLUDES=$(TESTINCLUDES) -I$(HASHMAPDIR) -I/liboqs/build/include/
SOURCES=$(SOURCEDIR)resource_record.c $(SOURCEDIR)question.c $(SOURCEDIR)crypto.c  \
	  $(HASHMAPDIR)map.c $(SOURCEDIR)dns_message.c

daemon: $(SOURCEDIR)daemon.c $(HASHMAPDIR)map.c $(SOURCES)
	$(CC) -o $@ -Wall -pedantic -g $^ -lnetfilter_queue -lrt -lm $(INCLUDES) -pthread -lcrypto -L/liboqs/build/lib/ -loqs
