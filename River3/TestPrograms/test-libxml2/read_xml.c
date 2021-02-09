#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

int RIVERTestOneInput(char *xmlStr)
{
    // Convert the input from RIVER into a valid, NULL-terminated, string
    size_t strLen = (size_t) xmlStr[0];
    char* str = (char *) malloc ((strLen + 1) * sizeof(char));

    memcpy(str, xmlStr + 1, strLen);
    str[strLen] = '\0';

    // Load the xml file from a string
    xmlDocPtr xmlDoc = xmlParseDoc((xmlChar *) str);
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
    ssize_t n_read = 0;

    if (argc != 2) {
        printf("First argument must be a valid XML document. "
               "The XML must be provided as a string to cli; this is not a path.\b");
        return -1;
    }

    size_t kMaxInputSize = 1 << 20;
    char inputBuf[kMaxInputSize];

    while (1) {
        n_read = read(0, inputBuf, kMaxInputSize);
        if (n_read > 0)
            rc = RIVERTestOneInput(inputBuf);
    }
    return rc;
}
