cmake_minimum_required(VERSION 3.10)

set(LIB_NAME "PcapLib")
project(${LIB_NAME})

set(LIB_SRC "src/PcapFileHandler.cpp" "src/MdUdpParser.cpp")
set(LIB_INC "src" "include")

add_library(${LIB_NAME} STATIC ${LIB_SRC})

target_include_directories(${LIB_NAME} PRIVATE ${LIB_INC})
