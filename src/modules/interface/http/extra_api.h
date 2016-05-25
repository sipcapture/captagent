
#ifndef _EXTRA_MODULES_INTERFACE_H_
#define _EXTRA_MODULES_INTERFACE_H_

#include "config.h"
#include "civetweb.h"

#ifdef  HAVE_JSON_C_JSON_H  
#include <json-c/json.h>
#elif HAVE_JSON_JSON_H   
#include <json/json.h>
#elif HAVE_JSON_H
#include <json.h>  
#endif


int check_extra_delete(struct mg_connection *conn, char *uri, json_object **jobj_reply, const char *requestUuid);
int check_extra_create(struct mg_connection *conn, char *uri, json_object **jobj_reply, char *post_data, const char *requestUuid);
int check_extra_update(struct mg_connection *conn, char *uri, json_object **jobj_reply, char *post_data, const char *requestUuid);
int check_extra_get(struct mg_connection *conn, char *uri, json_object **jobj_reply, const const char *requestUuid);

#endif

