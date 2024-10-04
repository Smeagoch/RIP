#ifndef INTERFACE_HPP
#define INTERFACE_HPP

#include <iostream>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <memory>

#include "route.hpp"
#include "rip_socket.hpp"

#define interface_flag_running 0x0001
#define interface_flag_passive 0x0100

// extern std::list<interface> interface_list;

struct interface {
	/* Configured information */
	std::string name;
    uint32_t index;

	uint32_t flags;
	uint32_t route_table;
	uint16_t afnum;
	/* TODO: storing few address on iface */
	uint32_t address;
	uint8_t address_prefix;

	std::unordered_map<int, std::shared_ptr<struct route>> route_htable;

	interface(const char *iface_name) : name(iface_name) {
		this->index = 0;

		this->flags = 0;
		this->route_table = 0;
		this->afnum = 0;
		this->address = 0;
	}
};

void interface_show();
std::shared_ptr<interface> interface_get_shared_by_name(const char *iface_name, bool create);
std::shared_ptr<interface> interface_get_shared_by_index(const char *iface_name, bool create);
interface *interface_get_by_index(uint32_t index);
bool interface_join_mcast_group(rip_socket &sock);

/* for_each functions */
// void interface_update

#endif /* INTERFACE_HPP */
