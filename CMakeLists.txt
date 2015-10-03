cmake_minimum_required(VERSION 3.0.0)
project(HostScanner)

if (CMAKE_COMPILER_IS_GNUCXX)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++14")
endif()

find_package(Boost 1.55.0 REQUIRED)
if (Boost_FOUND)
	include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
endif()

#set(SOURCES main.cpp)
file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

add_executable(HostScanner ${HEADERS} ${SOURCES})