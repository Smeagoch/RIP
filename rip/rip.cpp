#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>
#include <cstring>

#include <signal.h>

#define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#include <asio.hpp>
// #include <boost/asio.hpp>
// #include "rip_peer.hpp"

#include "common.hpp"
#include "interface.hpp"
#include "rip_socket.hpp"
#include "rip_packet.hpp"
#include "rip_protocol.hpp"
#include "system_netlink.hpp"

#define RIP_CONF_FILE "/etc/rip/rip.conf"

asio::io_context service;
rip_socket<rip_packet, RIP_PORT> rip_sock(service);

void signal_handler(const asio::error_code & err, int signal) 
{
    switch (signal)
    {
    case SIGINT:
        rip_sock.close();
        netlink_close();
        interface_cleanup();
        break;
    
    default:
        exit(0);
        break;
    }
}

bool load_conf()
{
    std::string conf_str;
    std::ifstream conf_file(RIP_CONF_FILE);
    if (!conf_file.is_open())
        return false;

    while (std::getline(conf_file, conf_str)) {
        char *word = std::strtok(conf_str.data(), " \n");
        if (strcmp(word, "network ")) {
            word = std::strtok(nullptr, " \n");
            if (strcmp(word, "10.10.10.10/24"))
                std::cout << word << std::endl; 
        }
    }

    conf_file.close();
    return true;
}

int main(int argc, char *argv[])
{ 
    // if (!load_conf())
    //     return 1;
    // char buf[20] = "100.100.11.2\0";

    asio::signal_set sig(service, SIGINT, SIGTERM);
    sig.async_wait(signal_handler);

    rip_sock.open();
    netlink_init();
    // rip_sock.join_mcast_group(buf);
    rip_sock.async_read();
    rip_sock.update_init();

    // if (strlen(buf) != 0)
    //  std::cout << "no null" << std::endl;

    service.run();

    return 0;
}
