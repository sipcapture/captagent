#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/capture.h>
#include <captagent/xmlread.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>
#include <dirent.h>
#include "md5.h"
#include <captagent/globals.h>
#include "captagent.h"
#include "config.h"
#include "modules/protocol/rtcp/parser_rtcp.h"

int cfg_errors = 0;
int debug = 0;
struct capture_list main_ct;
char *module_name_p = "";
char *global_node_name = NULL;
char *global_config_path = NULL;
int print_lic_exit = 0;
char *global_license = NULL;
int not_send = 0;
int flag_Lic = -1;      // License: 1 = activate; 0 = deactivate
int type_Lic = 1;
int count_big_down_jump = 0;
char *usefile = NULL;
unsigned long expireLicTime = 0;
int flag_is_lic_count_wrong = 0;
char hwk[33];
int flag_is_expire = 0;
int flag_is_invalid = 0;
int bytes_parsed = 0;

int main()
{
    /* MALFORMED RTCP RR PKT */
    // Correct pkt is 4 byte header + 4 bytes SSRC + 24 byte for every Report count (if exist)
    // in this case count == 1 (first byte 0x81)
    char rr[29] = {
        0x81, 0xc9, 0x00, 0x07, 0x54, 0xf2, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x81,
        0xc9, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };

    /* MALFORMED RTCP SR PKT */
    // Correct pkt is 4 byte header + 4 byte SSRC + 20 byte for sender info + 24 byte for every Report count (if exist)
    char sr[25] = {
        0x80, 0xc8, 0x00, 0x06, 0x22, 0xa1, 0x04, 0x02,
        0x83, 0xab, 0x11, 0x03, 0xeb, 0x00, 0x01, 0x3a,
        0x00, 0x00, 0x94, 0x20, 0x00, 0x00, 0x00, 0xfb,
        0x10,
    };

    
    char *json_rtcp_buffer;
    int ret, len;

    len = sizeof(sr);
    json_rtcp_buffer = calloc(5000, sizeof(char));
    ret = capt_parse_rtcp(&sr, len, json_rtcp_buffer, 5000);
    if(ret == -1 || ret == -2) {
        printf("capt_parse_rtcp :: error!\n");
    } else {
        printf("capt_parse_rtcp :: parsing correct\n");
    }
    if(json_rtcp_buffer) free(json_rtcp_buffer);

    printf("!!! IF WE ARE HERE NO CRASH DETECTED IN MEMORY !!!")
    return 0;
}
