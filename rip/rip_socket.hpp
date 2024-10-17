#ifndef RIP_SOCKET_HPP
#define RIP_SOCKET_HPP

#include <iostream>
#include <asio.hpp>
#include <linux/in.h>
#include <linux/ip.h>
#include <sys/socket.h>

#include "common.hpp"
#include "route.hpp"
#include "rip_protocol.hpp"
#include "rip_socket.hpp"
#include "rip_packet.hpp"

template <typename T = rip_packet, uint32_t port = 520>
class rip_socket {
private:
    struct sockaddr_in src_addr_;
    struct iovec iov_;
    struct msghdr msg_;
    asio::ip::udp::socket sock_;
    
    uint8_t buf_[8192];
    uint8_t cmsgbuf_[CMSG_SPACE(sizeof(struct in_pktinfo))];

    asio::steady_timer update_timer;

    void read_cb(std::size_t length, uint32_t ifi_index);
    void update_cb();

public:
    rip_socket(asio::io_service &service_);
    ~rip_socket();

    void open();
    void async_read();
    void update_init();
    void join_mcast_group(asio::ip::address_v4 local_addr);
    void close();
};

template <typename T, uint32_t port>
rip_socket<T, port>::rip_socket(asio::io_service &service_) : sock_(service_), update_timer(service) {}

template <typename T, uint32_t port>
rip_socket<T, port>::~rip_socket()
{
    if (sock_.is_open())
        close();
}

template <typename T, uint32_t port>
void rip_socket<T, port>::read_cb(std::size_t length, uint32_t ifi_index)
{
    T packet;

    if (!packet.get_iface(ifi_index))
        return;

    packet.unmarshall(this->buf_, length);

#ifdef DEBUG
    std::cout << "DEBUG: " << "Receive RIP packet:" << std::endl;
    packet.print();
#endif

    packet.handle();
}

template <typename T, uint32_t port>
void rip_socket<T, port>::update_cb()
{
    constexpr  std::size_t buff_size = RIP_ENTRY_SIZE * MAX_RIP_ENTRIES + RIP_HDR_SIZE;
    uint8_t buff[buff_size];

    T packet;
    asio::ip::udp::endpoint multicast_enpoint(asio::ip::make_address(RIP_MCAST_ADDR), RIP_PORT);

    packet.set_command(RIP_COMMAND_RESPONSE);
    packet.set_version(RIP_VERSION);

    for (const auto& pair : route_table) {
        packet.add_entry(pair.second.get());

        if (packet.entry_list_size() == MAX_RIP_ENTRIES) {
            uint16_t len = packet.marshall(buff, buff_size);
            std::cout << "INFO: Sending rip packet (len " << len << ")" << std::endl;
            this->sock_.send_to(asio::const_buffer(buff, len), multicast_enpoint);
            packet.entry_list_clear();
        }
    }

    if (packet.entry_list_size() != 0) {
        uint16_t len = packet.marshall(buff, buff_size);
        std::cout << "INFO: Sending rip packet (len " << len << ")" << std::endl;
        sock_.set_option(asio::ip::multicast::outbound_interface(asio::ip::address_v4::from_string("100.100.11.2")));
        this->sock_.send_to(asio::const_buffer(buff, len), multicast_enpoint);
    }
}

template <typename T, uint32_t port>
void rip_socket<T, port>::update_init()
{
        this->update_timer.expires_after(std::chrono::seconds(RIP_UPDATE_TIME));
        this->update_timer.async_wait(
            [this](const std::error_code &ec){
                if (ec == asio::error::operation_aborted)
                    return;
                
                if (ec)
                    return;

                this->update_cb();

                update_init();
            });
}

template <typename T, uint32_t port>
void rip_socket<T, port>::open()
{
    int enable = 1;
    asio::ip::address loc_address = asio::ip::address_v4::any();
    sock_.open(asio::ip::udp::v4());
    sock_.set_option(asio::ip::udp::socket::reuse_address(true));
    sock_.set_option(asio::ip::multicast::enable_loopback(false));
    setsockopt(this->sock_.native_handle(), IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));;
    sock_.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), port));
}

template <typename T, uint32_t port>
void rip_socket<T, port>::async_read()
{
    std::memset(&msg_, 0, sizeof(msg_));
    iov_.iov_base = buf_;
    iov_.iov_len = sizeof(buf_);
    msg_.msg_name = &src_addr_;
    msg_.msg_namelen = sizeof(src_addr_);
    msg_.msg_iov = &iov_;
    msg_.msg_iovlen = 1;
    msg_.msg_control = cmsgbuf_;
    msg_.msg_controllen = sizeof(cmsgbuf_);

    struct msghdr msg;
    sock_.async_receive(asio::null_buffers(),
        [this](const std::error_code &ec, std::size_t /* length */ ) {
            if (ec == asio::error::operation_aborted)
                    return;

            if (!ec) {
                struct cmsghdr* cmsg = nullptr;
                struct in_pktinfo* pktinfo = nullptr;

                std::size_t status = 0;
                if ((status = recvmsg(sock_.native_handle(), &msg_, 0)) < 0) {
                    perror("recvmsg");
                    return;
                }
                
                for (cmsg = CMSG_FIRSTHDR(&msg_); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg_, cmsg)) {
                    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                        pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
                        break;
                    }
                }

                if (pktinfo) {
                    read_cb(status, pktinfo->ipi_ifindex);
                } else {
                    throw std::runtime_error("IP_PKTINFO: emply control message");
                }
            }
            async_read();
        });
}

template <typename T, uint32_t port>
void rip_socket<T, port>::close()
{
    this->update_timer.cancel();
    this->sock_.cancel();
    this->sock_.close();
}

template <typename T, uint32_t port>
void rip_socket<T, port>::join_mcast_group(asio::ip::address_v4 local_addr)
{
    std::cerr << "join group : " << local_addr.to_string() << std::endl;
    this->sock_.set_option(asio::ip::multicast::join_group(
        asio::ip::address::from_string(RIP_MCAST_ADDR).to_v4(),
        local_addr));
        
}

#endif /* RIP_SOCKET_HPP */
