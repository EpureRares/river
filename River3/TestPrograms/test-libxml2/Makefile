CC=gcc
CFLAGS=`xml2-config --cflags`
LDFLAGS=`xml2-config --libs`

read_xml: read_xml.o
	$(CC) $^ -o $@ $(LDFLAGS)

read_xml.o: read_xml.c
	$(CC) -c $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f read_xml *.o
