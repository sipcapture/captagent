/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or modify
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


#include <stdio.h>
#include <stdlib.h>
#include <expat.h>
#include <string.h>

#include "api.h"
#include "xmlread.h"

xml_node *xml_alloc( xml_node *parent ) {
	xml_node *n, **link = &parent->child;

	if( (n = (xml_node *) malloc( sizeof( xml_node ) )) == NULL ) {
		fprintf( stderr, "Out of memory\n" );
		exit( 1 );
	}

	n->key = NULL;
	n->value = NULL;
	n->attr = NULL;
	n->child = NULL;
	n->next = NULL;
	n->parent = parent;

	while( *link != NULL ) {
		link = &(*link)->next;
	}

	return *link = n;
}

void xml_free( xml_node *node ) {
	int i;

	if( node == NULL )
		return;

	if( node->key != NULL )
		free( node->key );

	if( node->value != NULL )
		free( node->value );

	if( node->attr != NULL ) {
		for( i=0;node->attr[i];i++ )
			free( node->attr[i] );
		free( node->attr );
	}

	xml_free( node->next );
	xml_free( node->child );
}

void xml_el_start( void *data, const char *name, const char **attr ) {
	int i, nattr = 1;
	xml_node *node = xml_alloc( *((xml_node **) data) );

	if( node == NULL ) {
		fprintf( stderr, "Out of memory\n" );
		return;
	}

	node->key = strdup( name );

	for( i=0;attr[i];i++ )
		nattr++;

	if( (node->attr = (char **) malloc( sizeof( char * ) *nattr )) == NULL ) {
		fprintf( stderr, "Out of memory\n" );
		xml_free( node );
		return;
	}

	for( i=0;attr[i];i++ ) {
		node->attr[i] = strdup( attr[i] );
		//printf("ATTR: %s\n", attr[i]);
        }

	node->attr[i] = NULL;
		

	*((xml_node **) data) = node;
}

void xml_el_end( void *data, const char *name ) {
	xml_node *node = *((xml_node **) data);

	*((xml_node **) data) = node->parent;
}

void xml_charhndl( void *data, const char *s, int len ) {
	xml_node *node = *((xml_node **) data);	

	if( len > 0 )  node->value = strndup( s, len );		
}

xml_node *xml_parse( const char *filename ) {
	int done = 0;
	FILE *xptr;
	XML_Parser p;
	static char buf[BUFSIZE];
	xml_node root, *ret;

	if( (xptr = fopen( filename, "r" )) == NULL ) {
		fprintf( stderr, "Unable to open file: %s\n", filename );
		return NULL;
	}

	root.child = NULL;
	if( (ret = xml_alloc(&root)) == NULL ) {
		fclose( xptr );
		fprintf( stderr, "Out of memory\n" );
		return NULL;
	}

	if( (p = XML_ParserCreate( NULL )) == NULL ) {
		fclose( xptr );
		fprintf( stderr, "Out of memory\n" );
		return NULL;
	}

	XML_SetUserData( p, &ret );
	XML_SetElementHandler( p, xml_el_start, xml_el_end );
	XML_SetCharacterDataHandler( p, xml_charhndl );

	while( !done ) {
		int len;

		len = fread( buf, 1, BUFSIZE, xptr );
		if( ferror( xptr ) ) {
			fprintf( stderr, "Read error\n" );
			xml_free( ret );
			ret = NULL;
			break;
		}
		done = feof( xptr );

		if( XML_Parse(p, buf, len, done) == 0 ) {
			fprintf( stderr, "Parse error at line %d:\n%s\n",
							 (int) XML_GetCurrentLineNumber(p),
							 XML_ErrorString( XML_GetErrorCode(p) ) );
			xml_free( ret );
			ret = NULL;
			break;
		}
	}

	if( ret != NULL )
		ret->parent = NULL;

	fclose( xptr );
	XML_ParserFree( p );
	return ret;
}

xml_node *xml_get( const char *key, xml_node *ref, int recurs ) {
	xml_node *ret = NULL;

	if( ref->key != NULL && !strcmp( ref->key, key ) ) {
		return ref;
	}

	if( recurs && ref->child != NULL &&
			(ret = xml_get( key, ref->child, recurs )) != NULL ) {
		return ret;
	}

	if( ref->next != NULL && (ret = xml_get( key, ref->next, recurs )) != NULL ) {
		return ret;
	}

	return NULL;
}
