#include <iostream>
#include <asio.hpp>

#include "rip_protocol.hpp"
#include "rip_socket.hpp"
#include "rip_packet.hpp"

rip_socket::rip_socket(asio::io_service &service_) : sock_(service_) {}

rip_socket::~rip_socket()
{
    if (sock_.is_open())
        close();
}

void rip_socket::read_cb(std::size_t length, uint32_t ifi_index)
{
    rip_packet packet;

    if (!packet.get_iface(ifi_index))
        return;

    packet.unmarshall(this->buf_, length);

#ifdef DEBUG
    std::cout << "DEBUG: " << "Receive RIP packet:" << std::endl;
    packet.print();
#endif

    packet.handle();
}

void rip_socket::open()
{
    int enable = 1;
    asio::ip::address loc_address = asio::ip::address_v4::any();
    sock_.open(asio::ip::udp::v4());
    sock_.set_option(asio::ip::udp::socket::reuse_address(true));
    setsockopt(this->sock_.native_handle(), IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));;
    sock_.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), 520));
}

void rip_socket::async_read()
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

void rip_socket::close() { this->sock_.close(); }

void rip_socket::join_mcast_group(asio::ip::address_v4 local_addr)
{
    this->sock_.set_option(asio::ip::multicast::join_group(
        asio::ip::address::from_string(RIP_MCAST_ADDR).to_v4(),
        local_addr));
        
}
