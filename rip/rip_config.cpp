#include <fstream>
#include <sstream>
#include <stdexcept>

#include "rip_config.hpp"

void rip_config::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open configuretion file: " + filename);
    }

    std::string line;
    while (std::getline(file, line)) {
        line = line.substr(0, line.find('#'));
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (!line.empty()) {
            parse_line(line);
        }
    }
}

#ifdef DEBUG
void rip_config::print()
{
    for (auto net : networks) {
        std::cout << "network " << net.address
                << "/" << net.prefix_length << std::endl;
    }

    for (auto iface_name : passive_interfaces) {
        std::cout << "passive-interfaces " << iface_name << std::endl;
    }
}
#endif

void rip_config::parse_line(const std::string& line) {
    std::istringstream iss(line);
    std::string command;
    iss >> command;

    if (command == "network") {
        std::string network;
        iss >> network;
        parse_network(network);

    } else if (command == "passive-interface") {
        std::string iface;
        iss >> iface;
        passive_interfaces.insert(iface);

    } else if (command == "no-auto-summary") {
        auto_summary = false;

    } else {
        throw std::runtime_error("Unknown configuration command: " + command);
    }
}

void rip_config::parse_network(const std::string& network_str) {
    network network_info;

    size_t pos = network_str.find('/');

    if (pos == std::string::npos) {
        throw std::invalid_argument("Invalid network string: " + network_str);
    }

    network_info.address = network_str.substr(0, pos);
    network_info.prefix_length = std::stoi(network_str.substr(pos + 1));

    networks.push_back(network_info);
}

bool rip_config::is_passive_iface(const char * ifname)
{
    auto it = passive_interfaces.find(std::string(ifname));
    if (it != passive_interfaces.end()) 
        return true;

    return false;
}

bool rip_config::is_conf_network(std::string address, uint32_t prefix_length) {
    for (auto net : networks) {
        if (net.address == address &&
                net.prefix_length == prefix_length)
            return true;
    }

    return false;
}
