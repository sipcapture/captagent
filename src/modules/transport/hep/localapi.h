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

#ifndef TRANSPORT_HEP_API_H_
#define TRANSPORT_HEP_API_H_

#include <captagent/log.h>
#include <captagent/export_function.h>


extern int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int sendzip, unsigned int idx);
extern unsigned int get_profile_index_by_name(char *name);

typedef int (*hepapi_send_hep_f)(rc_info_t *rcinfo, unsigned char *data, unsigned int len, char *profile);
int hepapi_set_filter(rc_info_t *rcinfo, unsigned char *data, unsigned int len, char *profile);

typedef struct transport_hep_api {
	hepapi_send_hep_f    sendhep;
} transport_hep_api_t;

typedef int (*bind_transport_hep_f)(transport_hep_api_t* api);
int bind_transport_hep(transport_hep_api_t* api);

/**
 * @brief Load the socket_raw API
 */
static inline int transport_hep_load_api(transport_hep_api_t *api)
{
        bind_transport_hep_f bindtransport_hep;

        bindtransport_hep = (bind_transport_hep_f)find_export("bind_transport_hep", 0, 0);


        if(bindtransport_hep == 0) {
        	LERR("cannot find bind_transport hep\n");
                return -1;
        }
        if (bindtransport_hep(api) < 0)
        {
        	LERR("cannot bind transport_hep api\n");
                return -1;
        }
        return 0;
}


#endif /* TRANSPORT_HEP_API_H_ */
