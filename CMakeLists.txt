cmake_minimum_required(VERSION 3.10)

set (APP_NAME "PcapParser")
project(${APP_NAME})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory("lib")

set(APP_SRC "src/main.cpp")

add_executable(${APP_NAME} ${APP_SRC})

target_link_libraries(${APP_NAME} PRIVATE "PcapLib")
