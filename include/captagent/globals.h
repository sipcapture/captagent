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

#ifndef GLOBALS_H_
#define GLOBALS_H_

#define CT_NO 10 /* capture tables number */
#define DEFAULT_CT 0 /* default capture table */

#ifndef NULL
#define NULL ((void *)0)
#endif

extern int cfg_errors;

extern int debug;
extern int nofork;
extern int foreground;
extern int debug_level;
extern char *usefile;
extern char *global_license;
extern char *global_chroot;
extern char *global_config_path;
extern char *global_capture_plan_path;
extern char *global_uuid;
extern char *backup_dir;
extern int timestart;
extern int serial;
extern const char *captagent_config;

extern struct capture_list main_ct;

extern struct action* clist[20];

#endif /* GLOBALS_H_ */
