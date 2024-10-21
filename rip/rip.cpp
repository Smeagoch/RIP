#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>
#include <cstring>
#include <signal.h>
#include <getopt.h>
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

static void signal_handler(const asio::error_code & err, int signal) 
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

static int usage(const char *prog)
{
    std::cout << "usage: proto_rip [-d|--daemon]" << std::endl;
    std::cout << "\t-d, --daemon\t\t\t fork to background after startup" << std::endl;
    std::cout << std::endl;

    return 1;
}


static void daemonize() {
    pid_t pid = fork();

    if (pid < 0) {
        std::cerr << "ERROR: fork failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        std::cerr << "ERROR: Create new session failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    signal(SIGHUP, SIG_IGN);

    pid = fork();

    if (pid < 0) {
        std::cerr << "ERROR: Double fork failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (chdir("/") < 0) {
        std::cerr << "ERROR: Changing working directory failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}


int main(int argc, char *argv[])
{ 
    int c = 0;
    bool daemonmode = false;
	const struct option long_options[] =
	{
		{"admin-socket", required_argument, 0, 'a'},
		{"config-file", required_argument, 0, 'c'},
		{"script-file", required_argument, 0, 's'},
		{"pid-file", required_argument, 0, 'p'},
		{"log-level", required_argument, 0, 'l'},
		{"daemon", no_argument, 0, 'd'},
		{"Version", no_argument, 0, 'V'},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "c:s:a:p:dvV", long_options, NULL);
		if (c == -1)
        	break;

		switch (c) {
		case 'd':
			daemonmode = 1;
			break;
		default:
			return usage(argv[0]);
		}
	}

    configuration.load(RIP_CONF_FILE);

    asio::signal_set sig(service, SIGINT, SIGTERM);
    sig.async_wait(signal_handler);

    rip_sock.open();
    netlink_init();
    rip_sock.async_read();
    rip_sock.update_init();

    if (daemonmode)
        daemonize();

    service.run();

    return 0;
}
