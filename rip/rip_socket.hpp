#ifndef RIP_SOCKET_HPP
#define RIP_SOCKET_HPP

#include <iostream>
#include <asio.hpp>
#include <linux/in.h>
#include <linux/ip.h>
#include <sys/socket.h>

#include "common.hpp"

class rip_socket {
private:
    struct sockaddr_in src_addr_;
    struct iovec iov_;
    struct msghdr msg_;
    asio::ip::udp::socket sock_;
    
    uint8_t buf_[8192];
    uint8_t cmsgbuf_[CMSG_SPACE(sizeof(struct in_pktinfo))];

    void read_cb(std::size_t length, uint32_t ifi_index);

public:
    rip_socket(asio::io_service &service_);
    ~rip_socket();

    void open();
    void async_read();
    void join_mcast_group(asio::ip::address_v4 local_addr);
    void close();
};

#endif /* RIP_SOCKET_HPP */
