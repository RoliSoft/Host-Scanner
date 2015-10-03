cmake_minimum_required(VERSION 3.0.0)
project(HostScanner)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

find_package(Boost 1.55.0 REQUIRED)
if (Boost_FOUND)
	include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
endif()

#set(SOURCES main.cpp)
file(GLOB SOURCES "*.cpp")

add_executable(HostScanner ${SOURCES})