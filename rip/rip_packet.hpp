#ifndef RIP_PACKET_HPP
#define RIP_PACKET_HPP

#include <iostream>
#include <cstdint>
#include <vector>
#include <memory>

#include "common.hpp"
#include "route.hpp"

class rip_packet {
private:
    struct rip_entry {
        uint32_t ifi_index;

        uint16_t af_id;
        uint16_t route_tag;
        asio::ip::address_v4 dst_address;
        uint32_t subnet_mask;
        asio::ip::address_v4 next_hop_address;
        uint32_t metric;
    };

    uint32_t src_ifi_index;
    asio::ip::address_v4 src_address;

    uint8_t command;
    uint8_t version;
    uint16_t reserved;
    std::vector<rip_entry> rip_list;

public:
    void set_command(uint8_t command) { this->command = command; }
    void set_version(uint8_t version) { this->version = version; }
    void set_iface(uint32_t ifi_index);
    void set_address(asio::ip::address address);

    void unmarshall(uint8_t *pdu, uint32_t pdu_len);
    uint16_t marshall(uint8_t *pdu, uint32_t pdu_len, uint32_t iface_index);
    bool handle();
    bool add_entry(route *rt);
    uint8_t entry_list_size();
    void entry_list_clear();
    void print();
};

#endif /* RIP_PACKET_HPP */
