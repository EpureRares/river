#include <stdio.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

int RIVERTestOneInput(char *xmlStr)
{
    // Load the xml file from disk from a string
    xmlDocPtr xmlDoc = xmlParseDoc((xmlChar *) xmlStr);
    if (xmlDoc == NULL) {
        printf("Null doc\n");
        return -1;
    }

    // Do something with the document
    //....

    // Save the document back out to disk.
    //xmlSaveFileEnc("file.xml", xmlDoc, "UTF-8");

    xmlFreeDoc(xmlDoc);
    // Free the global variables that may have been allocated by the parser.
    xmlCleanupParser();

    return 0;
}

int main(int argc, char *argv[])
{
    int rc = 0;

    if (argc != 2) {
        printf("First argument must be a valid XML document. "
               "The XML must be provided as a string to cli; this is not a path.\b");
        return -1;
    }

    rc = RIVERTestOneInput(argv[1]);
    return rc;
}
