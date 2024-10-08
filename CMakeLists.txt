cmake_minimum_required(VERSION 3.13)

project(sdfs CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O3 -std=gnu++20 -gdwarf-2")

set(SDFS_VERSION_MAJOR 1)
set(SDFS_VERSION_MINOR 0)
set(SDFS_VERSION_PATCH 4)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBFUSE REQUIRED fuse3)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)
include_directories(PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

include_directories(PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/kernel_hdr")

add_subdirectory(src)

install(FILES sdfs-dd@.service sdfs-dd.target sdfs-dd-mgr.service sdfs-ctrl.service DESTINATION "/lib/systemd/system")
install(FILES sdfs.conf.sample DESTINATION /etc/sdfs)
