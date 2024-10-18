#include <iostream>
#include <unordered_map>
#include <memory>

#include "route.hpp"
#include "interface.hpp"

std::unordered_map<std::string, std::shared_ptr<route>> route_table;

static bool route_match(route *rt, route_selector *sel)
{
    if (sel == nullptr)
        return true;

    if (sel->ifi_index != 0 &&
            rt->ifi_index != sel->ifi_index)
        return false;

    if (!sel->dst_address.is_unspecified() != 0 &&
            rt->dst_address != sel->dst_address)
        return false;

    if (!sel->gateway.is_unspecified() != 0 &&
            rt->gateway != sel->gateway)
        return false;

    return true;
}

uint32_t route_v4_prefix(uint32_t subnet_mask)
{
    uint32_t count = 0;

    while (subnet_mask) {
        count += subnet_mask & 1;
        subnet_mask >>= 1;
    }

    return count;
}

uint32_t route_v4_submask(uint32_t prefix)
{
    uint32_t subnet_mask = 0;

    for (uint32_t i = prefix; i != 0; --i) {
        subnet_mask >>= 1;
        subnet_mask |= 0x80000000;
    }

    return subnet_mask;
}

void route_remove_matching(route_selector *sel)
{
    for (auto it = route_table.begin(); it != route_table.end();) {
        if (route_match(it->second.get(), sel)) {
            std::cout << "INFO: remove route to " << it->second->dst_address.to_string()
                    << "/" << it->second->prefix << std::endl;
            it = route_table.erase(it);
        } else {
            it++;
        }
    }
}

void route_purge_matching(route_selector *sel)
{
    for (auto it = route_table.begin(); it != route_table.end();) {
        if (route_match(it->second.get(), sel))
            if (it->second->type == route_type_static) {
                it->second->ifi_index = 0;

                if (it->second->dst_address.is_v4()) {
                    it->second->dst_address.to_v4().any();
                } else if (it->second->dst_address.is_v6()) {
                    it->second->dst_address.to_v6().any();
                }

                it->second->timer.cancel();

                it++;
            } else {
                it = route_table.erase(it);
            }
        else
            it++;
    }
}

void route_cleanup()
{
    route_remove_matching(nullptr);
}
