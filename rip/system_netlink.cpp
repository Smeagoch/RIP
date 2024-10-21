#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <asio.hpp>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "system_netlink.hpp"

#include "interface.hpp"
#include "route.hpp"
#include "rip_config.hpp"
#include "rip_socket.hpp"

static inline rtattr* NLMSG_Tail(nlmsghdr* nmsg){
	return (rtattr*) (((uint8_t*) nmsg) + NLMSG_ALIGN(nmsg->nlmsg_len));
}

static void netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    std::memset(tb, 0, sizeof(rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
}

static int netlink_add_rtattr_l(nlmsghdr* n, size_t maxlen, int type, const void *data, int alen)
{
	int len = RTA_LENGTH(alen);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return false;

	rtattr* rta = NLMSG_Tail(n);
	rta->rta_type = type;
	rta->rta_len = len;
	std::memcpy(RTA_DATA(rta), data, alen);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return true;
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

std::vector<netlink_socket> netlink_fd;

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
    if (reply == nullptr)
        return false;

    req->nlmsg_flags |= NLM_F_ACK;

    req->nlmsg_seq = increase_seq();
    int status = socket_.send(asio::const_buffer(req, req->nlmsg_len));

    if (status < 0) {
        perror("Cannot talk to rtnetlink");
        return false;
    }

    std::size_t length = socket_.receive(asio::buffer(buffer_));
    if (!handle_receive(length, reply, replysize))
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

        if (reply != nullptr && reply->nlmsg_seq == nh->nlmsg_seq) {
            if (replysize >= nh->nlmsg_len) {
                std::memcpy(reply, nh, replysize);
            } else {
                std::cerr << "WARNING: NLmsg truncated" << std::endl;
                std::memcpy(reply, nh, replysize);
            }
         } else if (nh->nlmsg_type < RTM_MAX &&
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
    interface *iface = interface_get_by_name(ifname, true);

    if (iface == nullptr)
        return;

    if (configuration.is_passive_iface(ifname))
        iface->flags |= interface_flag_passive;

    if (ifi->ifi_flags & IFF_RUNNING) {
        iface->flags |= interface_flag_running;
    } else {
        iface->flags &= ~interface_flag_running;

        route_selector sel;
        sel.ifi_index = iface->index;
        route_remove_matching(&sel);
    }

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
    interface *iface = interface_get_by_name(ifname, false);
    if (iface == NULL)
        return;

    std::cout << "INFO: " << "Interface " << ifname << " deleted" << std::endl;
    iface->flags &= ~interface_flag_running;

    route_selector sel;
    sel.ifi_index = iface->index;
    route_remove_matching(&sel);

    iface->index = 0;
}

static void netlink_addr_new(struct nlmsghdr *msg) {
    interface *iface;
    ifaddrmsg *ifa = (ifaddrmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[IFA_MAX + 1];

    netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
    iface = interface_get_by_index(ifa->ifa_index);
    if (iface == nullptr)
        return;

    if ((iface->flags & interface_flag_passive))
        return;

    if (rta[IFA_ADDRESS] != NULL) {
        /* TODO: handle IPv6 address */
        if (ifa->ifa_family == PF_INET)
        {
            iface->address = asio::ip::address_v4(ntohl(*((uint32_t *)RTA_DATA(rta[IFA_ADDRESS]))));
            iface->address_prefix = ifa->ifa_prefixlen;

            if (!iface->address.is_unspecified()) {
                rip_sock.join_mcast_group(iface->address);
            }
        } 

    }
}

/* TODO: leave multicast family */
static void netlink_addr_del(struct nlmsghdr *msg)
{
    interface *iface;
    ifaddrmsg *ifa = (ifaddrmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[IFA_MAX + 1];

    netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
    iface = interface_get_by_index(ifa->ifa_index);
    if (iface == nullptr)
        return;

    if ((iface->flags & interface_flag_passive))
        return;

    if (rta[IFA_ADDRESS] != NULL) {
        /* TODO: handle IPv6 address */
        if (ifa->ifa_family == PF_INET)
        {
            iface->address = asio::ip::address_v4(ntohl(*((uint32_t *)RTA_DATA(rta[IFA_ADDRESS]))));
            iface->address_prefix = ifa->ifa_prefixlen;

            if (!(iface->flags & interface_flag_passive) &&
                    !iface->address.is_unspecified()) {
                rip_sock.leave_mcast_group(iface->address);
            }
        } 

    }
}

static void netlink_route_new(struct nlmsghdr *msg)
{
    rtmsg *rtm = (rtmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[RTA_MAX+1];

    netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));

    if (rta[RTA_OIF] == NULL || rta[RTA_DST] == NULL)
		return;

    interface *iface = interface_get_by_index(*(uint8_t*)RTA_DATA(rta[RTA_OIF]));
    if (iface == nullptr)
        return;

    if (rtm->rtm_table != RT_TABLE_MAIN)
        return;

    /* TODO: handle IPv6 route */
    if (rtm->rtm_family == PF_INET) {
        asio::ip::address dst_address = asio::ip::address_v4(ntohl(*(uint32_t*)RTA_DATA(rta[RTA_DST])));
        uint32_t prefix = rtm->rtm_dst_len;

        if (configuration.is_conf_network(dst_address.to_string(), prefix)) {
            std::cout << "DEBUG: Adding static route to " << dst_address.to_string() << "/" << prefix << std::endl;

            route *new_route = new route;
            new_route->dst_address = dst_address;
            new_route->prefix = prefix;
            new_route->ifi_index = iface->index;

            if (rta[RTA_GATEWAY] != NULL)
                new_route->gateway =  asio::ip::address_v4(ntohl(*(uint8_t*)RTA_DATA(rta[RTA_GATEWAY])));

            new_route->type = route_type_static;
            new_route->flags = route_flag_up;
            new_route->hop = 1;

            route_table.insert(std::make_pair(new_route->dst_address.to_v4().to_string(), new_route));
        }
    }
}

static void netlink_route_del(struct nlmsghdr *msg)
{
    rtmsg *rtm = (rtmsg*)NLMSG_DATA(msg);
    struct rtattr *rta[RTA_MAX+1];

    netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));

    if (rta[RTA_OIF] == NULL || rta[RTA_DST] == NULL)
		return;

    /* TODO: handle IPv6 route */
    if (rtm->rtm_family == PF_INET) {
        asio::ip::address dst_address = asio::ip::address_v4(ntohl(*(uint32_t*)RTA_DATA(rta[RTA_DST])));
        auto rt = route_table.find(dst_address.to_string());
        if (rt == route_table.end())
            return;
        if (rt->second->type == route_type_static) {
            std::cout << "DEBUG: Remove static route to " << dst_address.to_string() << "/" << (uint32_t)rtm->rtm_dst_len << std::endl;
            route_table.erase(dst_address.to_string());
        } else {
            std::cout << "DEBUG: Replace dynamic route to " << dst_address.to_string() << "/" << (uint32_t)rtm->rtm_dst_len << std::endl;
            kernel_route_replace(rt->second);
        }
    }
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
    req.nlh.nlmsg_seq =  netlink_fd[TALK_FD].increase_seq();
    req.g.rtgen_family = AF_PACKET;

    netlink_fd[TALK_FD].send(&req.nlh);
    netlink_fd[TALK_FD].read();
}

bool kernel_route_replace(route *rt)
{
    struct {
        struct nlmsghdr 	n;
        struct rtmsg 		r;
        char   			buf[1024];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE | NLM_F_ACK;
    req.n.nlmsg_type = RTM_NEWROUTE;
    req.r.rtm_type = RTN_UNICAST;
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_RIP;

    if (rt->dst_address.is_v4()) {
        struct in_addr addr;
        req.r.rtm_family = PF_INET;

        addr.s_addr = htonl(rt->dst_address.to_v4().to_uint());
        netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST,
                    (char *)&addr, sizeof(struct in_addr));
        req.r.rtm_dst_len = rt->prefix;

        if (!rt->gateway.is_unspecified()) {
            addr.s_addr = htonl(rt->gateway.to_v4().to_uint());
            netlink_add_rtattr_l(&req.n, sizeof(req), RTA_GATEWAY,
                        (char *)&addr, sizeof(struct in_addr));
        }

    } else if (rt->dst_address.is_v6()) {
        /* TODO: need add attr for IPv6 address*/
        return false;
    } else {
        return false;
    }

    netlink_add_rtattr_l(&req.n, sizeof(req), RTA_OIF,
                    &rt->ifi_index, sizeof(int));
    
    if (!netlink_fd[TALK_FD].netlink_talk(&req.n, &req.n, sizeof(req)))
        return false;

    nlmsgerr *err = (nlmsgerr*)NLMSG_DATA(&req.n);
    if (err->error != 0) {
        std::cerr << "ERROR: netlink error \"" << strerror(- err->error) 
                << "\" about msg type %d" << err->msg.nlmsg_type << std::endl;
        return false;
    }

    return true;
}

bool kernel_route_del(route *rt)
{
    struct {
        struct nlmsghdr 	n;
        struct rtmsg 		r;
        char   			buf[1024];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = RTM_DELROUTE;
    req.r.rtm_type = RTN_UNICAST;
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_RIP;

    if (rt->dst_address.is_v4()) {
        struct in_addr addr;
        req.r.rtm_family = PF_INET;

        addr.s_addr = htonl(rt->dst_address.to_v4().to_uint());
        netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST,
                    (char *)&addr, sizeof(struct in_addr));
        req.r.rtm_dst_len = rt->prefix;

        if (!rt->gateway.is_unspecified()) {
            addr.s_addr = htonl(rt->gateway.to_v4().to_uint());
            netlink_add_rtattr_l(&req.n, sizeof(req), RTA_GATEWAY,
                        (char *)&addr, sizeof(struct in_addr));
        }

    } else if (rt->dst_address.is_v6()) {
        /* TODO: need add attr for IPv6 address*/
        return false;
    } else {
        return false;
    }

    netlink_add_rtattr_l(&req.n, sizeof(req), RTA_OIF,
                    &rt->ifi_index, sizeof(int));
    
    if (!netlink_fd[TALK_FD].netlink_talk(&req.n, &req.n, sizeof(req)))
        return false;

    nlmsgerr *err = (nlmsgerr*)NLMSG_DATA(&req.n);
    if (err->error != 0) {
        std::cerr << "ERROR: netlink error " << strerror(- err->error) 
                << " about msg type %d" << err->msg.nlmsg_type << std::endl;
        return false;
    }

    return true;
}

bool netlink_init() {
    netlink_fd.push_back(netlink_socket(service, 0));
    netlink_fd.push_back(netlink_socket(service, RTMGRP_LINK));
    netlink_fd.push_back(netlink_socket(service, RTMGRP_IPV4_IFADDR));
    netlink_fd.push_back(netlink_socket(service, RTMGRP_IPV4_ROUTE));

    netlink_dump(RTM_GETLINK);
    netlink_dump(RTM_GETADDR);
    netlink_dump(RTM_GETROUTE);

    netlink_fd[LINK_GROUP_FD].async_read();
    netlink_fd[ADDR_GROUP_FD].async_read();
    netlink_fd[ROUTE_GROUP_FD].async_read();

    return true;
}

bool netlink_close() {
    for (auto fd = netlink_fd.begin(); fd != netlink_fd.end(); fd++)
        fd->close();

    netlink_fd.clear();

    return true;
}
