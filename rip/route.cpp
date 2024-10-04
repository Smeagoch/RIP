#include <iostream>
#include <unordered_map>
#include <memory>

#include "route.hpp"
#include "interface.hpp"

std::unordered_map<int, std::shared_ptr<route>> route_table;
