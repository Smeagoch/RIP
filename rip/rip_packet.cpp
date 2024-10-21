#include <iostream>
#include <sys/socket.h>
#include <asio.hpp>

#include "rip_protocol.hpp"
#include "rip_packet.hpp"
#include "system_netlink.hpp"
#include "interface.hpp"
#include "route.hpp"

void rip_packet::set_iface(uint32_t ifi_index)
{
    this->src_ifi_index = ifi_index;
}

void rip_packet::set_address(asio::ip::address address)
{
    this->src_address = address.to_v4();
}

void rip_packet::unmarshall(uint8_t *pdu, uint32_t pdu_len)
{
    if (pdu_len < RIP_HDR_SIZE)
        throw std::runtime_error("Invalid RIP packet length");

    this->command = pdu[0];
    this->version = pdu[1];

    if (this->version != RIP_VERSION) {
        throw std::runtime_error("Unsupported RIP version");
    }
  
    size_t offset = RIP_HDR_SIZE;
    while (offset < pdu_len && this->rip_list.size() < MAX_RIP_ENTRIES) {
        if (pdu_len - offset < RIP_ENTRY_SIZE) {
            break;
        }

        rip_entry entry;
        entry.af_id = ntohs(*((uint16_t *) &pdu[offset]));
        offset += sizeof(uint16_t);

        entry.route_tag = ntohs(*((uint16_t *) &pdu[offset]));
        offset += sizeof(uint16_t);

        entry.dst_address = asio::ip::address_v4(ntohl(*((uint32_t *) &pdu[offset])));
        offset += sizeof(uint32_t);

        entry.subnet_mask = ntohl(*((uint32_t *) &pdu[offset]));
        offset += sizeof(uint32_t);

        entry.next_hop_address = asio::ip::address_v4(ntohl(*((uint32_t *) &pdu[offset])));
        offset += sizeof(uint32_t);
        if (entry.next_hop_address.is_unspecified())
            entry.next_hop_address = this->src_address;

        entry.metric = ntohl(*((uint32_t *) &pdu[offset]));
        offset += sizeof(uint32_t);

        this->rip_list.push_back(entry);
    }
}

uint16_t rip_packet::marshall(uint8_t *pdu, uint32_t pdu_len, uint32_t iface_index)
{
    if (pdu_len < RIP_HDR_SIZE)
        throw std::runtime_error("Not enough space in buffer");

    interface * iface = interface_get_by_index(iface_index);

    if (iface == nullptr)
        throw std::runtime_error("Cannot find device by index");

    size_t offset = RIP_HDR_SIZE;
    for (auto entry : this->rip_list) {
        if (offset + RIP_ENTRY_SIZE > pdu_len)
            throw std::runtime_error("Not enough space in buffer");

        if (entry.ifi_index == iface_index)
            continue;

        *((uint16_t*) &pdu[offset]) = htons(entry.af_id);
        offset += sizeof(uint16_t);

        *((uint16_t*) &pdu[offset]) = htons(entry.route_tag);
        offset += sizeof(uint16_t);

        *((uint32_t*) &pdu[offset]) = htonl(entry.dst_address.to_uint());
        offset += sizeof(uint32_t);

        *((uint32_t*) &pdu[offset]) = htonl(entry.subnet_mask);
        offset += sizeof(uint32_t);

        *((uint32_t*) &pdu[offset]) = htonl(iface->address.to_uint());
        offset += sizeof(uint32_t);

        *((uint32_t*) &pdu[offset]) = htonl(entry.metric);
        offset += sizeof(uint32_t);
    }

    if (offset == RIP_HDR_SIZE)
        return 0;

    pdu[0] = this->command;
    pdu[1] = this->version;

    return offset;
}

bool rip_packet::handle() {
    if (this->version != 2)
        std::cerr << "ERROR: Unsupported version" << std::endl; 

    if (this->command != RIP_COMMAND_RESPONSE)
        std::cerr << "ERROR unsupported command" << std::endl;

    for (const auto &entry : this->rip_list) {
        route *rt_ptr = nullptr;
        bool is_change = false;

        if (entry.metric >= MAX_RIP_METRIC)
            continue;

        auto rt = route_table.find(entry.dst_address.to_string());
        if (rt != route_table.end()) {
            rt_ptr = rt->second;
            if (rt_ptr->hop < entry.metric + 1)
                return false;
        }

        if (rt_ptr == nullptr) {
            std::cout << "DEBUG: " << "Adding dynamic route to " << entry.dst_address.to_string() 
                    << "/" << route_v4_prefix(entry.subnet_mask) << " metric " << entry.metric << std::endl;
            route *new_route = new route;
            new_route->dst_address = entry.dst_address;
            new_route->type = route_type_dynamic;
            route_table.insert(std::make_pair(new_route->dst_address.to_v4().to_string(), new_route));
            rt_ptr = new_route;
        }

        if (rt_ptr->ifi_index != this->src_ifi_index) {
            rt_ptr->ifi_index = this->src_ifi_index;

            is_change = true;
        }

        if (rt_ptr->gateway.to_v4() != entry.next_hop_address) {
            rt_ptr->gateway = entry.next_hop_address;
            is_change = true;
        }

        if (rt_ptr->prefix != route_v4_prefix(entry.subnet_mask)) {
            rt_ptr->prefix = route_v4_prefix(entry.subnet_mask);
            /* TODO: maybe set prefix for address */
            is_change = true;
        }

        rt_ptr->hop = entry.metric + 1;

        if (is_change)
            kernel_route_replace(rt_ptr);

        rt_ptr->timer.cancel_one();
        rt_ptr->timer.expires_after(std::chrono::seconds(RIP_EXPIRE_TIME));
        rt_ptr->timer.async_wait(
            [rt_ptr](const std::error_code &ec){
                if (ec == asio::error::operation_aborted)
                    return;
                
                if (ec)
                    return;
                std::cout << "DEBUG: " << "Removing expired route to " << rt_ptr->dst_address.to_string()
                        << " metric " << rt_ptr->metric << std::endl;
                route_table.erase(rt_ptr->dst_address.to_string());
            });
    }

    return true;
}

bool rip_packet::add_entry(route *rt)
{
    rip_entry entry;
    entry.ifi_index = rt->ifi_index;
    entry.af_id = PF_INET;
    entry.dst_address = rt->dst_address.to_v4();
    entry.metric = rt->hop;

    if (!entry.next_hop_address.is_unspecified())
        entry.next_hop_address = rt->gateway.to_v4();
    else
        entry.next_hop_address = interface_get_by_index(entry.ifi_index)->address;
    entry.route_tag = 0;
    entry.subnet_mask = route_v4_submask(rt->prefix);

    this->rip_list.push_back(entry);
    
    return true;
}

uint8_t rip_packet::entry_list_size()
{
    return this->rip_list.size();
}

void rip_packet::entry_list_clear()
{
    this->rip_list.clear();
}

void rip_packet::print() {
    std::cout << "  Command: " << (int)this->command << std::endl;
    std::cout << "  Version: " << (int)this->version << std::endl;
    std::cout << "  Entries: " << this->rip_list.size() << std::endl;

    for (const auto &entry : this->rip_list) {
        std::cout << "    IP: " << entry.dst_address.to_string() 
                << "/" << route_v4_prefix(entry.subnet_mask)
                << " Metric: " << entry.metric << std::endl;
    }
}
