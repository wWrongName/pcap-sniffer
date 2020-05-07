cmake_minimum_required(VERSION 3.10)

project(sniffer)

set(SOURCE_EXE sniff.c)

set(SOURCE_LIB s_func.c)

add_library(s_func ${SOURCE_LIB})

add_executable(sniff ${SOURCE_EXE})

target_link_libraries(sniff s_func)