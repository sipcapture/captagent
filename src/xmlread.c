/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or
 * modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * Homer capture agent is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
*/

#ifndef XMLREAD_C_
#define XMLREAD_C_

#include <stdio.h>
#include <stdlib.h>
#include <expat.h>
#include <string.h>

#include <captagent/log.h>
#include <captagent/api.h>
#include <captagent/xmlread.h>

xml_node *xml_alloc(xml_node *parent) {
	xml_node *n, **link = &parent->child;

	if ((n = (xml_node *) malloc(sizeof(xml_node))) == NULL) {
		LERR("Out of memory\n");
		exit(1);
	}

	n->key = NULL;
	n->value = NULL;
	n->attr = NULL;
	n->child = NULL;
	n->next = NULL;
	n->parent = parent;

	while (*link != NULL) {
		link = &(*link)->next;
	}

	return *link = n;
}

void xml_free(xml_node *node) {
	int i;

	if (node == NULL)
		return;

	if (node->key != NULL)
		free(node->key);

	if (node->value != NULL)
		free(node->value);

	if (node->attr != NULL) {
		for (i = 0; node->attr[i]; i++)
			free(node->attr[i]);
		free(node->attr);
	}

	xml_free(node->next);
	xml_free(node->child);
}

void xml_el_start(void *data, const char *name, const char **attr) {
	int i, nattr = 1;
	xml_node *node = xml_alloc(*((xml_node **) data));

	if (node == NULL) {
		LERR("Out of memory node");
		return;
	}

	node->key = strdup(name);

	for (i = 0; attr[i]; i++)
		nattr++;

	if ((node->attr = (char **) malloc(sizeof(char *) * nattr)) == NULL) {
		LERR("Out of memory node attr");
		xml_free(node);
		return;
	}

	for (i = 0; attr[i]; i++) {
		node->attr[i] = strdup(attr[i]);
		//printf("ATTR: %s\n", attr[i]);
	}

	node->attr[i] = NULL;

	*((xml_node **) data) = node;
}

void xml_el_end(void *data, const char *name) {
	xml_node *node = *((xml_node **) data);

	*((xml_node **) data) = node->parent;
}

void xml_charhndl(void *data, const char *s, int len) {
	xml_node *node = *((xml_node **) data);

	if (len > 0)
		node->value = strndup(s, len);
}

xml_node *xml_parse(const char *filename) {
	int done = 0;
	FILE *xptr;
	XML_Parser p;
	static char buf[BUFSIZE];
	xml_node root, *ret;

	if ((xptr = fopen(filename, "r")) == NULL) {
		LERR("Unable to open file: [%s]", filename);
		return NULL;
	}

	root.child = NULL;
	if ((ret = xml_alloc(&root)) == NULL) {
		fclose(xptr);
		LERR("Out of memory root child");
		return NULL;
	}

	if ((p = XML_ParserCreate( NULL)) == NULL) {
		fclose(xptr);
		LERR("Out of memory parser create");
		return NULL;
	}

	XML_SetUserData(p, &ret);
	XML_SetElementHandler(p, xml_el_start, xml_el_end);
	XML_SetCharacterDataHandler(p, xml_charhndl);

	while (!done) {
		int len;

		len = fread(buf, 1, BUFSIZE, xptr);
		if (ferror(xptr)) {
			LERR("Read error");
			xml_free(ret);
			ret = NULL;
			break;
		}
		done = feof(xptr);

		if (XML_Parse(p, buf, len, done) == 0) {
			LERR("Parse error at line [%d]:[%s]", (int ) XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
			xml_free(ret);
			ret = NULL;
			break;
		}
	}

	if (ret != NULL)
		ret->parent = NULL;

	fclose(xptr);
	XML_ParserFree(p);
	return ret;
}


int xml_parse_with_report(const char *filename, char *erbuf, int erlen) {
	int done = 0, myval=1;
	FILE *xptr;
	XML_Parser p;
	static char buf[BUFSIZE];
	xml_node root, *ret;

	if ((xptr = fopen(filename, "r")) == NULL) {
		snprintf(erbuf, erlen,"Unable to open file: [%s]", filename);
		return 0;
	}

	root.child = NULL;
	if ((ret = xml_alloc(&root)) == NULL) {
		fclose(xptr);
		snprintf(erbuf, erlen, "Out of memory root child");
		return 0;
	}

	if ((p = XML_ParserCreate( NULL)) == NULL) {
		fclose(xptr);
		snprintf(erbuf, erlen,"Out of memory parser create");
		return 0;
	}

	XML_SetUserData(p, &ret);
	XML_SetElementHandler(p, xml_el_start, xml_el_end);
	XML_SetCharacterDataHandler(p, xml_charhndl);

	while (!done) {
		int len;
		len = fread(buf, 1, BUFSIZE, xptr);
		if (ferror(xptr)) {
			snprintf(erbuf, erlen, "Read error");
			xml_free(ret);
			ret = NULL;
			myval = 0;
			break;
		}
		done = feof(xptr);

		if (XML_Parse(p, buf, len, done) == 0) {
			snprintf(erbuf, erlen, "Parse error at line [%d]:[%s]", (int ) XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
			xml_free(ret);
			ret = NULL;
			myval = 0;
			break;
		}
	}

	if (ret != NULL)
		ret->parent = NULL;

	fclose(xptr);
	XML_ParserFree(p);
	if(ret) xml_free(ret);
	return myval;
}


xml_node *xml_node_str(char *str, int len) {
	FILE *xptr;
	XML_Parser p;
	static char buf[BUFSIZE];
	xml_node root, *ret;

    if(NULL == str) return NULL;

	root.child = NULL;
	if ((ret = xml_alloc(&root)) == NULL) {
		LERR("Out of memory root child");
		return NULL;
	}

	if ((p = XML_ParserCreate( NULL)) == NULL) {
		LERR("Out of memory parser create");
		return NULL;
	}

	XML_SetUserData(p, &ret);
	XML_SetElementHandler(p, xml_el_start, xml_el_end);
	XML_SetCharacterDataHandler(p, xml_charhndl);

	if (XML_Parse(p, str, len, 1) == 0) {
		LERR("Parse error at line [%d]:[%s]", (int ) XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
		xml_free(ret);
		ret = NULL;
	}

	if (ret != NULL)
		ret->parent = NULL;

	XML_ParserFree(p);
	return ret;
}


xml_node *xml_get(const char *key, xml_node *ref, int recurs) {
	xml_node *ret = NULL;

	if (ref->key != NULL && !strcmp(ref->key, key)) {
		return ref;
	}

	if (recurs && ref->child != NULL && (ret = xml_get(key, ref->child, recurs)) != NULL) {
		return ret;
	}

	if (ref->next != NULL && (ret = xml_get(key, ref->next, recurs)) != NULL) {
		return ret;
	}

	return NULL;
}



#endif /* XMLREAD_C_ */
