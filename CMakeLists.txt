cmake_minimum_required(VERSION 3.20)

set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(SRC_DIR ${ROOT_DIR}/rip)
set(LIB_DIR ${SRC_DIR}/build)

project(proto_rip)

add_executable(${PROJECT_NAME}
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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -c -Wall -ggdb")

# add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
#     COMMAND cp ${PROJECT_NAME} ${ROOT_DIR}/${PROJECT_NAME}
#     COMMENT "[post] Create disassemble file ${PROJECT_NAME}.dis"
# )
