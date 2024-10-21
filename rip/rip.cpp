#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>
#include <cstring>
#include <signal.h>
#include <asio.hpp>

#include "common.hpp"
#include "interface.hpp"
#include "rip_config.hpp"
#include "rip_socket.hpp"
#include "rip_packet.hpp"
#include "rip_protocol.hpp"
#include "system_netlink.hpp"
#define RIP_CONF_FILE "/etc/rip/rip.conf"

asio::io_context service;
rip_socket<rip_packet, RIP_PORT> rip_sock(service);
rip_config configuration;

void signal_handler(const asio::error_code & err, int signal) 
{
    switch (signal)
    {
    case SIGINT:
        rip_sock.close();
        route_cleanup();
        netlink_close();
        interface_cleanup();
        break;
    
    default:
        exit(0);
        break;
    }
}

int main(int argc, char *argv[])
{ 

    configuration.load(RIP_CONF_FILE);
#ifdef DEBUG
    configuration.print();
#endif

    asio::signal_set sig(service, SIGINT, SIGTERM);
    sig.async_wait(signal_handler);

    rip_sock.open();
    netlink_init();
    rip_sock.async_read();
    rip_sock.update_init();

    service.run();

    return 0;
}
