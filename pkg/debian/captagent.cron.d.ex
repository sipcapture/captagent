#
# Regular cron jobs for the captagent package
#
0 4	* * *	root	[ -x /usr/bin/captagent_maintenance ] && /usr/bin/captagent_maintenance
