cmake_minimum_required(VERSION 3.10)

project(sniffer)

add_definitions(-DWPCAP -DHAVE_REMOTE)

include(FindPCAP.cmake)

set(SOURCE_EXE sniff.c)

set(SOURCE_LIB s_func.c)

add_library(s_func ${SOURCE_LIB})

add_executable(sniffer ${SOURCE_EXE})

target_link_libraries(sniffer s_func)

target_link_libraries(sniffer ${PCAP_LIBRARY})