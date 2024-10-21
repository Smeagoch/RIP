#ifndef RIP_PROTOCOL_HPP
#define RIP_PROTOCOL_HPP

#define RTPROT_RIP      189
#define RIP_PORT        520
#define RIP_VERSION     2

enum {
    RIP_COMMAND_UNSPEC = 0,
    RIP_COMMAND_REQUEST,
    RIP_COMMAND_RESPONSE,
};

#define RIP_HDR_SIZE    4
#define RIP_ENTRY_SIZE  20

#define MAX_RIP_ENTRIES 25
#define MAX_RIP_METRIC  16

#define RIP_MCAST_ADDR  "224.0.0.9"

#define RIP_EXPIRE_TIME 300
#define RIP_UPDATE_TIME 30

#endif /* RIP_PROTOCOL_HPP */
