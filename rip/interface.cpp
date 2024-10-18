#include <iostream>
#include <algorithm>
#include <string>
#include <cstring>
#include <list>
#include <memory>
#include <array>

#include "common.hpp"
#include "interface.hpp"

std::list<interface*> interface_list;

#ifdef DEBUG
void interface_show()
{
    std::for_each(interface_list.begin(), interface_list.end(), [](interface *iface) {
        std::cout << "DEBUG: " << "Interface configuration:" << std::endl;
        std::cout << "  interface : " << iface->name << std::endl;
        std::cout << "    index: " << iface->index << std::endl;
        std::cout << "    address: " << iface->address.to_string() << std::endl;;
    });
}
#endif

interface *interface_get_by_name(const char *iface_name, bool create)
{
    interface *iface_ptr = nullptr;

    if (!interface_list.empty()) {
        for (interface *iface : interface_list) {
            if (iface->name.compare(iface_name) == 0)
                iface_ptr = iface;
        }
    }

    if (iface_ptr == nullptr & create) {
        interface *iface = new interface(iface_name);
        interface_list.push_back(iface);
        iface_ptr = iface;
    }

    return iface_ptr;
}

interface *interface_get_by_index(uint32_t index)
{
    if (interface_list.empty())
        return nullptr;

    for (interface *iface : interface_list) {
        if (iface->index == index)
            return iface;
    }

    return nullptr;
}

void interface_cleanup()
{
    for (interface *iface : interface_list)
        delete iface;

    interface_list.clear();
}
