#ifndef RIP_CONFIG_H
#define RIP_CONFIG_H

#include <string>
#include <vector>
#include <set>
#include <iostream>

#include "common.hpp"

class rip_config {
private:
    struct network {
        uint8_t af_fm;
        std::string address;
        uint32_t prefix_length;
    };

    std::vector<network> networks;
    std::set<std::string> passive_interfaces;
    bool auto_summary = true;

    void parse_line(const std::string& line);
    void parse_network(const std::string& network_str);
public:
    void load(const std::string& filename);
#ifdef DEBUG    
    void print();
#endif
    bool is_passive_iface(const char *ifname);
    bool is_conf_network(std::string address, uint32_t prefix_length);
};

#endif /* RIP_CONFIG_H */
