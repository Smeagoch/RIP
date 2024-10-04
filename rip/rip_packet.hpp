#ifndef RIP_PACKET_HPP
#define RIP_PACKET_HPP

#include <iostream>
#include <cstdint>
#include <vector>
#include <memory>

#include "interface.hpp"

struct rip_entry {
    uint16_t af_id;
    uint16_t route_tag;
    uint32_t dst_address;
    uint32_t subnet_mask;
    uint32_t next_hop_address;
    uint32_t metric;
};

struct ext_rip_entry {
    struct interface *iface;
    rip_entry entry;
};

class rip_packet {
private:
    struct interface *src_iface;

    uint8_t command;
    uint8_t version;
    uint16_t reserved;
    std::vector<ext_rip_entry> rip_list;

public:
    bool unmarshall(uint8_t *pdu, uint32_t pdu_len);
    bool handle();
    bool send();
    bool add_entry();
    void print();

    bool get_iface(uint32_t ifi_index);

private:
    bool marshall();
};

#endif /* RIP_PACKET_HPP */
