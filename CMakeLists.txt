cmake_minimum_required(VERSION 3.10)

set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(SRC_DIR ${ROOT_DIR}/rip)
set(LIB_DIR ${SRC_DIR}/build)

project(proto_rip VERSION 1.0.0)

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

set(CPACK_PACKAGE_NAME "proto_rip")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_CONTACT "nniikk2001@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION "Routing Information Protocol")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/Smeagoch/RIP")

set(CPACK_GENERATOR DEB)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Smeagoch <nniikk2001@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libasio-dev")
set(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

install(TARGETS proto_rip RUNTIME DESTINATION /usr/bin/)
install(FILES etc/rip.conf DESTINATION /etc/rip/)
install(FILES lib/systemd/system/proto_rip.service DESTINATION /lib/systemd/system/)

include(CPack)
