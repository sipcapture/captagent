/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Holger Hans Peter Freyther <help@moiji-mobile.com>
 *  (C) Homer Project 2016 (http://www.sipcapture.org)
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

#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>

static int ss7_load_module(xml_node *config);
static int ss7_unload_module(void);
static int ss7_description(char *description);
static int ss7_statistic(char *buf, size_t len);
static uint64_t ss7_serial_module(void);

static uint64_t module_serial = 0;

static cmd_export_t ss7_cmds[] = {
	{ 0, },
};

struct module_exports exports = {
	.name		= "protocol_ss7",
        .cmds		= ss7_cmds,
        .load_f		= ss7_load_module,
        .unload_f	= ss7_unload_module,
        .description_f	= ss7_description,
        .stats_f	= ss7_statistic,
        .serial_f	= ss7_serial_module,
};

static int ss7_load_module(xml_node *config)
{
	return 0;
}

static int ss7_unload_module(void)
{
	return 0;
}

static int ss7_description(char *description)
{
	return 1;
}

static int ss7_statistic(char *buf, size_t len)
{
	return 1;
}

static uint64_t ss7_serial_module(void)
{
	return module_serial;
}
