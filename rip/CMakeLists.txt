cmake_minimum_required(VERSION 3.20)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

project(rip)

set(SOURCE_FILES
    ${SRC_DIR}/interface.cpp
    ${SRC_DIR}/route.cpp
    ${SRC_DIR}/rip_packet.cpp
    ${SRC_DIR}/system_netlink.cpp
    ${SRC_DIR}/rip_config.cpp
    ${SRC_DIR}/rip.cpp
)

include_directories(
    ${SRC_DIR}
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -c -Wall -ggdb")

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
