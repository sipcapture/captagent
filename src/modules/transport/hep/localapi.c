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


#include <stdio.h>
#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>
#include "localapi.h"


/**
 *
 */
int hepapi_send_hep(rc_info_t *rcinfo, char *data, unsigned int len, char *profile)
{
    //set_raw_filter(index, filter);
    unsigned int idx = 0;

    idx = get_profile_index_by_name(profile);                      

    send_hepv3(rcinfo, data, len, 0, idx);
    
    LDEBUG("SEND HEP! [%d]\n", idx);
    return 1;
}

/**
 *
 */
int bind_transport_hep(transport_hep_api_t* api)
{
        if (!api) {
        	LERR("Invalid parameter value\n");
                return -1;

        }
        api->sendhep  = hepapi_send_hep;

        return 0;
}


