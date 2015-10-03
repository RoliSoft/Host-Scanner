cmake_minimum_required(VERSION 3.3.2)
project(HostScanner)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

find_package(Boost 1.59.0 REQUIRED)
if (Boost_FOUND)
	include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
endif()

add_executable(HostScanner main.cpp)