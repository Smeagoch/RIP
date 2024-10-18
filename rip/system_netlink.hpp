#ifndef SYSTEM_NETLINK_HPP
#define SYSTEM_NETLINK_HPP

#include <iostream>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <asio.hpp>

#include "common.hpp"

template <typename Protocol>
class nl_endpoint
{
private:
    sockaddr_nl sockaddr;
public:
    typedef Protocol protocol_type;
    typedef asio::detail::socket_addr_type data_type;        

    nl_endpoint()
    {
        std::memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.nl_family = AF_NETLINK;
        sockaddr.nl_groups = 0;
        // sockaddr.nl_pid = getpid();
    }

    nl_endpoint(int group)
    {
        std::memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.nl_family = AF_NETLINK;
        sockaddr.nl_groups = group;
        // sockaddr.nl_pid = getpid();
    }

    nl_endpoint(const nl_endpoint& other)
    {
        std::memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr = other.sockaddr;
    }

    nl_endpoint& operator=(const nl_endpoint& other)
    {
        sockaddr = other.sockaddr;
        return *this;
    }

    protocol_type protocol() const
    {
        return protocol_type();
    }

    data_type* data()
    {
        return (struct sockaddr*) &sockaddr;
    }

    const data_type* data() const
    {
        return (struct sockaddr*) &sockaddr;
    }

    std::size_t size() const
    {
        return sizeof(sockaddr);
    }

    void resize(std::size_t size)
    {
    /* nothing we can do here */
    }

    std::size_t capacity() const
    {
        return sizeof(sockaddr);
    }

    friend bool operator==(const nl_endpoint<Protocol>& e1,
               const nl_endpoint<Protocol>& e2)
    {
        if (memcmp(&e1.sockaddr, &e2.sockaddr, sizeof(sockaddr)) == 0)
            return true;

        return false;
    }

    friend bool operator!=(const nl_endpoint<Protocol>& e1,
               const nl_endpoint<Protocol>& e2)
    {
        if (memcmp(&e1.sockaddr, &e2.sockaddr, sizeof(sockaddr)) != 0)
            return true;

        return false;
    }

    friend bool operator<(const nl_endpoint<Protocol>& e1,
              const nl_endpoint<Protocol>& e2)
    {
        if (memcmp(&e1.sockaddr, &e2.sockaddr, sizeof(sockaddr)) < 0)
            return true;

        return false;
    }

    friend bool operator>(const nl_endpoint<Protocol>& e1,
              const nl_endpoint<Protocol>& e2)
    {
        if (memcmp(&e1.sockaddr, &e2.sockaddr, sizeof(sockaddr)) < 0)
            return true;

        return false;
    }

    friend bool operator<=(const nl_endpoint<Protocol>& e1,
               const nl_endpoint<Protocol>& e2)
    {
        return !(e2 < e1);
    }

    friend bool operator>=(const nl_endpoint<Protocol>& e1,
               const nl_endpoint<Protocol>& e2)
    {
        return !(e1 < e2);
    }
};

class nl_protocol
{
private:
    int proto; 
public:
    nl_protocol() { proto = 0; }
    nl_protocol(int proto) { this->proto = proto; }

    int type() const { return SOCK_RAW; }

    int protocol() const { return proto; }

    int family() const { return AF_NETLINK; }

    typedef nl_endpoint<nl_protocol> endpoint;
    typedef asio::basic_raw_socket<nl_protocol> socket;
};

class netlink_socket {
private:
    asio::basic_raw_socket<nl_protocol> socket_; 
    std::array<char, 16000> buffer_;
    uint32_t seq;

private:
    bool handle_receive(std::size_t length,
            struct nlmsghdr *reply, size_t replysize);

public:
    netlink_socket(asio::io_context& sevice, int group);
    uint32_t increase_seq() {return seq++;}
    void async_read();
    void close() { socket_.close(); }
    void read();
    bool send(struct nlmsghdr *req);
    bool netlink_talk(struct nlmsghdr *req,
            struct nlmsghdr *reply, size_t replysize);
};

bool netlink_init();
bool netlink_close();

#endif /* SYSTEM_NETLINK_HPP */
