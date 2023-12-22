cmake_minimum_required(VERSION 3.16)
project(ru_hava)

set(CMAKE_CXX_STANDARD 17)

add_executable(ru_hava main.cpp
        m.cpp
        m.h
        t.cpp
        t.h)

find_package(PcapPlusPlus REQUIRED)

set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)