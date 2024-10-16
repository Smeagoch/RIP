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
    asio::ip::address_v4 dst_address;
    uint32_t subnet_mask;
    asio::ip::address_v4 next_hop_address;
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
    void set_command(uint8_t command) { this->command = command; }
    void set_version(uint8_t version) { this->version = version; }

    bool unmarshall(uint8_t *pdu, uint32_t pdu_len);
    uint16_t marshall(uint8_t *pdu, uint32_t pdu_len);
    bool handle();
    bool add_entry(route *rt);
    uint8_t entry_list_size();
    void entry_list_clear();
    void print();

    bool get_iface(uint32_t ifi_index);
};

#endif /* RIP_PACKET_HPP */
