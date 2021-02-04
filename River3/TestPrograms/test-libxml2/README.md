# Dummy XML parser

`read_xml` is a simple XML reader program.
It uses [libxml](http://xmlsoft.org/html/libxml-parser.html#xmlParseDoc) to parse CLI arguments.

## Building

In order to be able to build, make sure that `libxml2` and `libxml2-dev` are installed.
Once you've installed the `libxml` library, use the `Makefile`:

```
$ make
```

## Running

Just provide a string at CLI

```
$ ./read_xml "<my_tag>Ok xml document</my_tab>"


$ ./read_xml "Bad doc"
Entity: line 1: parser error : Start tag expected, '<' not found
Bad doc
^
Null doc
```
