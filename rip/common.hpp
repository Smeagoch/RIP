#ifndef COMMON_HPP
#define COMMON_HPP

#include <asio.hpp>

#define DEBUG

struct rip_socket;

extern asio::io_context service;
extern rip_socket rip_sock;

#endif /* COMMON_HPP */
