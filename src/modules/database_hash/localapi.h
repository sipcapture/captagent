/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
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


#ifndef DATABASE_HASH_API_H_
#define DATABASE_HASH_API_H_

#include "src/log.h"
#include "src/export_function.h"

typedef char* (*hashapi_lookup_f)(char *ip, int port);
char* hashapi_lookup(char *ip, int port);


typedef struct database_hash_api {
        hashapi_lookup_f  lookup;
} database_hash_api_t;

typedef int (*bind_database_hash_f)(database_hash_api_t* api);
int bind_database_hash(database_hash_api_t* api);

/**
 * @brief Load the database_hash API
 */
static inline int database_hash_load_api(database_hash_api_t *api)
{
        bind_database_hash_f binddatabase_hash;

        binddatabase_hash = (bind_database_hash_f)find_export("bind_database_hash", 0, 0);

        if(binddatabase_hash == 0) {
        	LERR("cannot find bind_database_hash\n");
            return -1;
        }

        if (binddatabase_hash(api) < 0)
        {
        	LERR("cannot bind database_hash api\n");
                return -1;
        }

        return 0;
}



#endif /* DATABASE_HASH_API_H_ */
