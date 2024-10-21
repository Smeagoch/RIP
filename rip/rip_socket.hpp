#ifndef RIP_SOCKET_HPP
#define RIP_SOCKET_HPP

#include <iostream>
#include <asio.hpp>
#include <linux/in.h>
#include <linux/ip.h>
#include <sys/socket.h>

#include "common.hpp"
#include "route.hpp"
#include "interface.hpp"
#include "rip_protocol.hpp"
#include "rip_socket.hpp"
#include "rip_packet.hpp"

template <typename T = rip_packet, uint32_t port = 520>
class rip_socket {
private:
    struct sockaddr_storage src_addr_;
    struct iovec iov_;
    struct msghdr msg_;
    asio::ip::udp::socket sock_;
    
    uint8_t buf_[8192];
    uint8_t cmsgbuf_[CMSG_SPACE(sizeof(struct in_pktinfo))];

    asio::steady_timer update_timer;

    void read_cb(std::size_t length, uint32_t ifi_index, asio::ip::address);

public:
    rip_socket(asio::io_service &service_);
    ~rip_socket();

    void open();
    void async_read();
    void update_init();
    void update();
    void join_mcast_group(asio::ip::address local_addr);
    void leave_mcast_group(asio::ip::address local_addr);
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
void rip_socket<T, port>::read_cb(std::size_t length,
            uint32_t ifi_index, asio::ip::address address)
{
    T packet;

    packet.set_iface(ifi_index);
    packet.set_address(address);

    try {
        packet.unmarshall(this->buf_, length);
    } catch (const char *error_message) {
        std::cerr << "Failed to unmarshalling packet: " << error_message << std::endl;
        return;
    }
    

    std::cout << "INFO: " << "Receive RIP packet from "<< address << ":" << std::endl;
    packet.print();

    packet.handle();
}

template <typename T, uint32_t port>
void rip_socket<T, port>::update()
{
    constexpr  std::size_t buff_size = RIP_ENTRY_SIZE * MAX_RIP_ENTRIES + RIP_HDR_SIZE;
    uint8_t buff[buff_size] = {0};

    T packet;

    auto send = [this, &packet, buff, &buff_size](const interface *iface) {
                if (iface->flags & interface_flag_passive)
                    return;

                if (!(iface->flags & interface_flag_running))
                    return;

                if (iface->name.compare("lo") == 0)
                    return;

                if (iface->address.is_unspecified())
                    return;

                uint16_t len = 0;
                try {
                    len = packet.marshall((uint8_t *)buff, buff_size, iface->index);
                } catch (const char *message) {
                    std::cerr << "ERROR: Failed to marshalling packet to " 
                            << iface->name << ": " << message << std::endl;
                    return;
                }
                if (len == 0)
                    return;

                this->sock_.set_option(asio::ip::multicast::outbound_interface(iface->address));
                asio::ip::udp::endpoint multicast_enpoint(asio::ip::make_address(RIP_MCAST_ADDR), RIP_PORT);
                this->sock_.send_to(asio::const_buffer(buff, len), multicast_enpoint);
    };

    packet.set_command(RIP_COMMAND_RESPONSE);
    packet.set_version(RIP_VERSION);

    for (const auto& pair : route_table) {
        packet.add_entry(pair.second);

        if (packet.entry_list_size() == MAX_RIP_ENTRIES) {
            std::cout << "INFO: " << "Sending RIP packet:" << std::endl;
            packet.print();
            std::for_each(interface_list.begin(), interface_list.end(), send);
            packet.entry_list_clear();
        }
    }

    if (packet.entry_list_size() != 0) {
        std::cout << "INFO: " << "Sending RIP packet:" << std::endl;
        packet.print();
        std::for_each(interface_list.begin(), interface_list.end(), send);
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

                this->update();

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

            if (ec) {
                std::cerr << "ERROR: rip_socket receive error: " << ec.message() << std::endl;
            } else {
                struct cmsghdr* cmsg = nullptr;
                struct in_pktinfo* pktinfo = nullptr;
                asio::ip::address src_address;

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

                if (msg_.msg_namelen == sizeof(struct sockaddr_in))
                    src_address = asio::ip::address_v4(ntohl(reinterpret_cast<struct sockaddr_in *>(msg_.msg_name)->sin_addr.s_addr));
                else if (msg_.msg_namelen == sizeof(struct sockaddr_in6))
                    std::cerr << "WARNING: Processing of ipv6 addresses is not supported" << std::endl;
                else
                    std::cerr << "WARNING: Unsupported address" << std::endl;

                if (pktinfo == nullptr)
                    std::cerr << "ERROR: IP_PKTINFO: emply control message" << std::endl;

                if (pktinfo && !src_address.is_unspecified())
                    read_cb(status, pktinfo->ipi_ifindex, src_address);
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

/* TODO: need function for ipv6 */
template <typename T, uint32_t port>
void rip_socket<T, port>::join_mcast_group(asio::ip::address local_addr)
{
    std::cerr << "INFO: join multicast group: " << local_addr.to_string() << std::endl;
    this->sock_.set_option(asio::ip::multicast::join_group(
        asio::ip::address::from_string(RIP_MCAST_ADDR).to_v4(),
        local_addr.to_v4()));
}

/* TODO: need function for ipv6 */
template <typename T, uint32_t port>
void rip_socket<T, port>::leave_mcast_group(asio::ip::address local_addr)
{
    std::cerr << "INFO: leave group : " << local_addr.to_string() << std::endl;

    this->sock_.set_option(asio::ip::multicast::leave_group(
        asio::ip::address::from_string(RIP_MCAST_ADDR).to_v4(),
        local_addr.to_v4()));
}

#endif /* RIP_SOCKET_HPP */
