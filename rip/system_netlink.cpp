#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <asio.hpp>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "common.hpp"
#include "system_netlink.hpp"
#include "interface.hpp"
#include "route.hpp"

static void netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    std::memset(tb, 0, sizeof(rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
}

static void netlink_error(struct nlmsghdr *msg);
static void netlink_link_new(struct nlmsghdr *msg);
static void netlink_link_del(struct nlmsghdr *msg);
static void netlink_addr_new(struct nlmsghdr *msg);
static void netlink_addr_del(struct nlmsghdr *msg);
static void netlink_route_new(struct nlmsghdr *msg);
static void netlink_route_del(struct nlmsghdr *msg);

enum {
    TALK_FD = 0,
    LINK_GROUP_FD,
    ADDR_GROUP_FD,
    ROUTE_GROUP_FD,
    MAX_FD
};

std::vector<std::shared_ptr<netlink_socket>> netlink_fd;

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg);

struct StaticArrayInit {
    netlink_dispatch_f Functions[RTM_MAX] = {0};

    constexpr auto operator[](size_t idx) const { return Functions[idx]; }
    constexpr size_t caddr_t()const { return RTM_MAX; }

    constexpr StaticArrayInit() {
        Functions[NLMSG_ERROR] = netlink_error;
        Functions[RTM_NEWLINK] = netlink_link_new;
        Functions[RTM_DELLINK] = netlink_link_del;
        Functions[RTM_NEWADDR] = netlink_addr_new;
        Functions[RTM_DELADDR] = netlink_addr_del;
        Functions[RTM_NEWROUTE] = netlink_route_new;
        Functions[RTM_DELROUTE] = netlink_route_del;
   }
};

static constexpr StaticArrayInit route_dispatch;

netlink_socket::netlink_socket(asio::io_service& service, int group) : socket_(service), seq(0) {

    socket_.open(nl_protocol(NETLINK_ROUTE));
    fcntl(socket_.native_handle(), F_SETFD, FD_CLOEXEC);

    socket_.non_blocking(true);
    socket_.bind(nl_endpoint<nl_protocol>(group));
}

bool netlink_socket::send(struct nlmsghdr *req)
{
    if (socket_.send(asio::const_buffer(req, req->nlmsg_len)))
        return true;
    
    return false;
}

bool netlink_socket::netlink_talk(struct nlmsghdr *req, struct nlmsghdr *reply, size_t replysize)
{
    if (reply == NULL)
        req->nlmsg_flags |= NLM_F_ACK;

    req->nlmsg_seq = increase_seq();

    buffer_.fill(0);
    memcpy((uint8_t *) buffer_.data(), (uint8_t *) req, req->nlmsg_len);
    int status = socket_.send(asio::buffer(buffer_));

    if (status < 0) {
        perror("Cannot talk to rtnetlink");
        return false;
    }

    if (reply == NULL)
        return true;

    std::size_t length = socket_.receive(asio::buffer(buffer_));
    if (handle_receive(length, reply, replysize) == 0)
        return false;

    return true;
}

void netlink_socket::async_read() {
    socket_.async_receive(asio::buffer(buffer_),
        [this](std::error_code ec, std::size_t length) {
            if (ec == asio::error::operation_aborted)
                    return;

            if (!ec) {
                handle_receive(length, nullptr, 0);
                async_read();
            } else {
                std::cerr << "ERROR: rip receive: " << ec.message() << std::endl;
            }
        });
}

void netlink_socket::read()
{
    size_t length = 0;
    while (1) {
        asio::error_code ec;
        length = socket_.receive(asio::buffer(buffer_), 0 , ec);
        if (ec == asio::error::would_block)
            break;
        else if (ec)
            std::cerr << "ERROR: netlink receive: " << ec.message() << std::endl;
        else
            handle_receive(length, nullptr, 0);
    }
}

bool netlink_socket::handle_receive(std::size_t length,
        struct nlmsghdr *reply, size_t replysize) {
    struct nlmsghdr* nh = (struct nlmsghdr*)buffer_.data();

    for (; NLMSG_OK(nh, length); nh = NLMSG_NEXT(nh, length)) {
        if (nh->nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (nh->nlmsg_type < RTM_MAX &&
            route_dispatch[nh->nlmsg_type] != NULL) {
            route_dispatch[nh->nlmsg_type](nh);
        } else if (nh->nlmsg_type != NLMSG_DONE) {
            std::cerr << "ERROR: " << "Unknown NLmsg: " << nh->nlmsg_type << std::endl;
        }
    }

    return true;
}

static void netlink_error(struct nlmsghdr *msg)
{
    struct nlmsgerr *err = (nlmsgerr*)NLMSG_DATA(msg);
    if (err->error != 0)
        std::cerr << "ERROR: " << "netlink error about msg type "
            <<  err->msg.nlmsg_type << "(see rtnetlink.h): "
            << strerror(- err->error) << std::endl;
}

static void netlink_link_new(struct nlmsghdr *msg)
{
    struct ifinfomsg *ifi = (ifinfomsg*)NLMSG_DATA(msg);
    struct rtattr *rta[IFLA_MAX + 1];

    netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
    if (rta[IFLA_IFNAME] == nullptr)
        return;

    char *ifname = ((char*)RTA_DATA(rta[IFLA_IFNAME]));
    std::shared_ptr<interface> iface = interface_get_shared_by_name(ifname, true);

    if (iface == nullptr)
        return;

    if (ifi->ifi_flags & IFF_RUNNING)
        iface->flags |= interface_flag_running;
    else
        iface->flags &= ~interface_flag_running;

    if (((ifi->ifi_change & IFF_UP) || (iface->index == 0)) &&
      (ifi->ifi_flags & IFF_UP))
        std::cout << "INFO: " << "Interface " << ifname << ": configured UP" << std::endl;
    else
        std::cout << "INFO: " << "Interface " << ifname << ": config change" << std::endl;

    iface->index = ifi->ifi_index;

    return;
}

static void netlink_link_del(struct nlmsghdr *msg)
{
    ifinfomsg *ifi = (ifinfomsg*)NLMSG_DATA(msg);
    struct rtattr *rta[IFLA_MAX + 1];

    netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
    if (rta[IFLA_IFNAME] == NULL)
        return;

    char *ifname = ((char*)RTA_DATA(rta[IFLA_IFNAME]));
    std::shared_ptr<interface> iface = interface_get_shared_by_name(ifname, false);
    if (iface == NULL)
        return;

    std::cout << "INFO: " << "Interface " << ifname << " deleted" << std::endl;
    iface->flags &= ~interface_flag_running;
    iface->index = 0;

    // address_set_type(&iface->nbma_address, PF_UNSPEC);
    // address_set_type(&iface->protocol_address, PF_UNSPEC);
}

static void netlink_addr_new(struct nlmsghdr *msg) {
    interface *iface;
    ifaddrmsg *ifa = (ifaddrmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[IFA_MAX + 1];

    netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
    iface = interface_get_by_index(ifa->ifa_index);
    if (iface == nullptr)
        return;

    if (rta[IFA_ADDRESS] != NULL) {
        /* TODO: handle IPv6 address */
        if (ifa->ifa_family == PF_INET)
        {
            iface->address = asio::ip::address_v4(ntohl(*((uint32_t *)RTA_DATA(rta[IFA_ADDRESS]))));
            iface->address_prefix = ifa->ifa_prefixlen;

            if (!(iface->flags & interface_flag_passive) && !iface->address.is_unspecified()) {
                rip_sock.join_mcast_group(iface->address);
            }
        } 

    }
}
static void netlink_addr_del(struct nlmsghdr *msg) {}

static void netlink_route_new(struct nlmsghdr *msg)
{
    rtmsg *rtm = (rtmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[RTA_MAX+1];

    netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));

}

static void netlink_route_del(struct nlmsghdr *msg)
{
    rtmsg *rtm = (rtmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[RTA_MAX+1];

    netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));

}

static void netlink_dump(uint32_t nlmsg_type)
{
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;

    std::memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = nlmsg_type;
    req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    req.nlh.nlmsg_pid = getpid();
    req.nlh.nlmsg_seq =  netlink_fd[TALK_FD]->increase_seq();
    req.g.rtgen_family = AF_PACKET;

    netlink_fd[TALK_FD]->send(&req.nlh);
    netlink_fd[TALK_FD]->read();
}

bool kernel_route_add(route rt);
bool kernel_route_del(route rt);

bool netlink_init() {
    auto talk_sock = std::make_shared<netlink_socket>(netlink_socket(service, 0));
    auto link_sock = std::make_shared<netlink_socket>(netlink_socket(service, RTMGRP_LINK));
    auto addr_sock = std::make_shared<netlink_socket>(netlink_socket(service, RTMGRP_IPV4_IFADDR));
    auto route_sock = std::make_shared<netlink_socket>(netlink_socket(service, RTMGRP_IPV4_ROUTE));

    netlink_fd.push_back(talk_sock);
    netlink_fd.push_back(link_sock);
    netlink_fd.push_back(addr_sock);
    netlink_fd.push_back(route_sock);

    netlink_dump(RTM_GETLINK);
    netlink_dump(RTM_GETADDR);
    netlink_dump(RTM_GETROUTE);

#ifdef DEBUG
    interface_show();
#endif

    // netlink_fd[TALK_FD]->async_read();
    netlink_fd[LINK_GROUP_FD]->async_read();
    netlink_fd[ADDR_GROUP_FD]->async_read();
    netlink_fd[ROUTE_GROUP_FD]->async_read();

    return true;
}

bool netlink_close() {
    for (auto fd : netlink_fd)
        fd->close();

    netlink_fd.clear();

    return true;
}
