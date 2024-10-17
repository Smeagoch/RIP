#ifndef ROUTE_HPP
#define ROUTE_HPP

#include <iostream>
#include <cstdint>
#include <memory>
#include <cstring>
#include <asio.hpp>

#include "common.hpp"

struct route;

extern std::unordered_map<int, std::shared_ptr<route>> route_table;

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

    asio::ip::address_v4 dst_address;
    asio::ip::address_v4 gateway;

    uint8_t prefix;
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

#endif /* ROUTE_HPP */
