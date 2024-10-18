#ifndef ROUTE_HPP
#define ROUTE_HPP

#include <iostream>
#include <cstdint>
#include <memory>
#include <cstring>
#include <asio.hpp>

#include "common.hpp"

struct route;

extern std::unordered_map<std::string, std::shared_ptr<route>> route_table;

#define route_type_static 0x01  /* static entry for configuration */
#define route_type_dynamic 0x02 /* dynamic entry for neighbor */

#define route_typemask_all ( \
    route_type_static | \
    route_type_dynamic)

#define route_flag_up 0x01

struct route {
public:
    uint32_t ifi_index;

    uint8_t type;
    uint8_t flags;

    asio::ip::address dst_address;
    asio::ip::address gateway;

    uint32_t prefix;
    uint32_t metric;

    uint32_t hop;

    asio::steady_timer timer;

    route() : timer(service)
    {
        ifi_index = 0;
        type = 0;
        flags = 0;

        prefix = 0;
        metric = 0;

        hop = 0;
    }
};

struct route_selector {
    uint32_t ifi_index;
    uint8_t type;
    asio::ip::address dst_address;
    uint8_t prefix;
    asio::ip::address gateway;

    route_selector()
    {
        uint8_t type = 0;
        ifi_index = 0;
        prefix = 0;
    }
};
uint32_t route_v4_submask(uint32_t prefix);
uint32_t route_v4_prefix(uint32_t subnet_mask);

void route_remove_matching(route_selector *sel);
void route_cleanup();

#endif /* ROUTE_HPP */
