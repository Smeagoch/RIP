#include <iostream>
#include <sys/socket.h>
#include <asio.hpp>

#include "common.hpp"
#include "rip_protocol.hpp"
#include "rip_packet.hpp"
#include "route.hpp"

bool rip_packet::get_iface(uint32_t ifi_index)
{
    this->src_iface = interface_get_by_index(ifi_index);

    if(this->src_iface == nullptr)
        return false;

    return true;
}

bool rip_packet::unmarshall(uint8_t *pdu, uint32_t pdu_len)
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

        ext_rip_entry ext_entry;
        ext_entry.entry.af_id = ntohs(*((uint16_t *) &pdu[offset]));
        offset += sizeof(uint16_t);

        ext_entry.entry.route_tag = ntohs(*((uint16_t *) &pdu[offset]));
        offset += sizeof(uint16_t);

        ext_entry.entry.dst_address = asio::ip::address_v4(ntohl(*((uint32_t *) &pdu[offset])));
        offset += sizeof(uint32_t);

        ext_entry.entry.subnet_mask = ntohl(*((uint32_t *) &pdu[offset]));
        offset += sizeof(uint32_t);

        ext_entry.entry.next_hop_address = asio::ip::address_v4(ntohl(*((uint32_t *) &pdu[offset])));
        offset += sizeof(uint32_t);

        ext_entry.entry.metric = ntohl(*((uint32_t *) &pdu[offset]));
        offset += sizeof(uint32_t);
        
        this->rip_list.push_back(ext_entry);
    }

    return true;
}

uint16_t rip_packet::marshall(uint8_t *pdu, uint32_t pdu_len)
{
    if (pdu_len < RIP_HDR_SIZE)
        throw std::runtime_error("Invalid RIP packet length");
    
    pdu[0] = this->command;
    pdu[1] = this->version;

    size_t offset = RIP_HDR_SIZE;
    for (auto ext_entry : this->rip_list) {
        if (offset + RIP_ENTRY_SIZE > pdu_len)
            throw std::runtime_error("Invalid RIP packet length");

        *((uint16_t*) &pdu[offset]) = ext_entry.entry.af_id;
        offset += sizeof(uint16_t);

        *((uint16_t*) &pdu[offset]) = ext_entry.entry.route_tag;
        offset += sizeof(uint16_t);

        *((uint32_t*) &pdu[offset]) = htonl(ext_entry.entry.dst_address.to_uint());
        offset += sizeof(uint32_t);

        *((uint32_t*) &pdu[offset]) = ext_entry.entry.subnet_mask;
        offset += sizeof(uint32_t);

        *((uint32_t*) &pdu[offset]) = htonl(ext_entry.entry.next_hop_address.to_uint());
        offset += sizeof(uint32_t);

        *((uint32_t*) &pdu[offset]) = ext_entry.entry.metric;
        offset += sizeof(uint32_t);
    }

    return offset;
}

bool rip_packet::handle() {
    if (this->version != 2)
        std::cerr << "ERROR: Unsupported version" << std::endl; 

    if (this->command != RIP_COMMAND_RESPONSE)
        std::cerr << "ERROR unsupported command" << std::endl;

    for (const auto &rt_entry : this->rip_list) {
        route *rt_ptr = nullptr;
        bool is_change = false;

        if (rt_entry.entry.metric >= MAX_RIP_METRIC)
            continue;

        auto rt = route_table.find(rt_entry.entry.dst_address.to_uint());
        if (rt != route_table.end()) {
            rt_ptr = rt->second.get();
            if (rt_ptr->metric < rt_entry.entry.metric)
                return false;
        }

        if (rt_ptr == nullptr) {
#ifdef DEBUG
            std::cout << "DEBUG: " << "Adding new route to " << rt_entry.entry.dst_address.to_string() << " metric " << rt_entry.entry.metric << std::endl;
#endif
            auto new_route = std::make_shared<route>(route());
            new_route->dst_address = rt_entry.entry.dst_address;
            route_table.insert(std::make_pair(new_route->dst_address.to_uint(), new_route));
            rt_ptr = new_route.get();
        }

        if (rt_ptr->iface == nullptr || rt_ptr->iface->name != this->src_iface->name) {
            if (rt_ptr->iface != nullptr)
                rt_ptr->iface->route_htable.erase(rt_ptr->dst_address.to_uint());
            rt_ptr->iface = interface_get_shared_by_name(this->src_iface->name.c_str(), false);
            rt_ptr->iface->route_htable.insert(std::make_pair(rt_ptr->dst_address.to_uint(),
                    route_table.find(rt_ptr->dst_address.to_uint())->second));

            is_change = true;
        }

        if (rt_ptr->gateway != rt_entry.entry.next_hop_address) {
            rt_ptr->gateway = rt_entry.entry.next_hop_address;
            is_change = true;
        }

        if (rt_ptr->prefix != rt_entry.entry.subnet_mask) {
            rt_ptr->prefix = rt_entry.entry.subnet_mask;
            // TODO: maybe set prefix for address
            is_change = true;
        }

        rt_ptr->metric = rt_entry.entry.metric;

        /* TODO: if is_change need update system route */

        rt_ptr->timer.cancel_one();
        rt_ptr->timer.expires_after(std::chrono::seconds(RIP_EXPIRE_TIME));
        rt_ptr->timer.async_wait(
            [rt_ptr](const std::error_code &ec){
                if (ec == asio::error::operation_aborted)
                    return;
                
                if (ec)
                    return;
#ifdef DEBUG
                std::cout << "DEBUG: " << "Removing expired route to " << rt_ptr->dst_address.to_string()
                        << " metric " << rt_ptr->metric << std::endl;
#endif
                route_table.erase(rt_ptr->dst_address.to_uint());
                rt_ptr->iface->route_htable.erase(rt_ptr->dst_address.to_uint());
            });
    }

    return true;
}

bool rip_packet::add_entry(route *rt)
{
    ext_rip_entry ext_entry;
    ext_entry.iface = rt->iface.get();
    ext_entry.entry.af_id = PF_INET;
    ext_entry.entry.dst_address = rt->dst_address;
    ext_entry.entry.metric = rt->hop;

    if (!ext_entry.entry.next_hop_address.is_unspecified())
        ext_entry.entry.next_hop_address = rt->gateway;
    else
        ext_entry.entry.next_hop_address = ext_entry.iface->address;
    ext_entry.entry.route_tag = 0;
    ext_entry.entry.subnet_mask = rt->prefix;

    this->rip_list.push_back(ext_entry);
    
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

    for (const auto &ext_entry : this->rip_list) {
        std::cout << "    IP: " << ext_entry.entry.dst_address.to_string()
                << " Metric: " << ext_entry.entry.metric << std::endl;
    }
}
