#ifndef XMLREAD_H
#define XMLREAD_H

xml_node *xml_parse( const char *filename );
xml_node *xml_get( const char *key, xml_node *ref, int recurs );

#define BUFSIZE 8192

#endif

