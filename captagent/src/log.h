#include <syslog.h>

void init_log(char *_prgname, int _use_syslog);

void set_log_level(int level);

void destroy_log(void);

void capt_log(int priority, char * format, ...);

#define LEMERG(fmt, args...) capt_log(LOG_EMERG, fmt, ## args)
#define LALERT(fmt, args...) capt_log(LOG_ALERT, fmt, ## args)
#define LCRIT(fmt, args...) capt_log(LOG_CRIT, fmt, ## args)
#define LERR(fmt, args...) capt_log(LOG_ERR, fmt, ## args)
#define LWARNING(fmt, args...) capt_log(LOG_WARNING, fmt, ## args)
#define LNOTICE(fmt, args...) capt_log(LOG_NOTICE, fmt, ## args)
#define LINFO(fmt, args...) capt_log(LOG_INFO, fmt, ## args)
#define LDEBUG(fmt, args...) capt_log(LOG_DEBUG, fmt, ## args)

