#ifndef ROUTE_HPP
#define ROUTE_HPP

#include <iostream>
#include <cstdint>
#include <memory>
#include <cstring>
#include <asio.hpp>

#include "common.hpp"
#include "interface.hpp"

struct route;
// struct rt_table;

extern std::unordered_map<int, std::shared_ptr<route>> route_table;

#define route_type_static 0x01  /* static entry for configuration */
#define route_type_dynamic 0x02 /* dynamic entry for neighbor */

#define route_typemask_all ( \
    route_type_static | \
    route_type_dynamic)

#define route_flag_up 0x01

class route {
public:
    std::shared_ptr<struct interface> iface;

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
        type = 0;
        flags = 0;

        prefix = 0;
        metric = 0;

        hop = 0;
    }
};

// class rt_table {
// private:
//     std::unordered_map<int, std::shared_ptr<route>> htable;

// public:
//     rt_table() {htable.reserve(1000);}
//     ~rt_table() = default;

//     bool update(struct rip_entry entry, interface *iface);
//     bool remove(uint32_t dst);
// };

#endif /* ROUTE_HPP */
