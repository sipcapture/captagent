/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov
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
#include <captagent/log.h>

#include <sys/types.h>
#include <limits.h>


static uint64_t module_serial = 0;

static cmd_export_t epan_cmds[] = {
	{
		.name		= "parse_epan",
		.function	= epan_parse,
		.param_no	= 0,
		.flags		= 0,
		.fixup_flags	= 0,
	},
	{ 0, },
};

struct module_exports exports = {
	.name		= "protocol_epan",
        .cmds		= epan_cmds,
        .load_f		= epan_load_module,
        .unload_f	= epan_unload_module,
        .description_f	= epan_description,
        .stats_f	= epan_statistic,
        .serial_f	= epan_serial_module,
};


static int epan_load_module(xml_node *config)
{
	return 0;
}

static int epan_unload_module(void)
{
	return 0;
}

static int epan_description(char *description)
{
	return 1;
}

static int epan_statistic(char *buf, size_t len)
{
	return 1;
}

static uint64_t epan_serial_module(void)
{
	return module_serial;
}
