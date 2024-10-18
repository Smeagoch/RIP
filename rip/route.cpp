#include <iostream>
#include <unordered_map>
#include <memory>

#include "route.hpp"
#include "interface.hpp"

std::unordered_map<int, std::shared_ptr<route>> route_table;

void route_cleanup()
{
    for (auto pair : route_table) {
        pair.second->timer.cancel();
        /* TODO: delete route for system */
    }

    route_table.clear();
}
