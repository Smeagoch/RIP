#ifndef COMMON_HPP
#define COMMON_HPP

#include <asio.hpp>

#include "rip_protocol.hpp"

template<typename T, uint32_t port>
class rip_socket;
class rip_packet;
class rip_config;

extern rip_config configuration;
extern asio::io_context service;
extern rip_socket<rip_packet, RIP_PORT> rip_sock;

#endif /* COMMON_HPP */
