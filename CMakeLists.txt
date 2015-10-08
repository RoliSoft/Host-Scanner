cmake_minimum_required(VERSION 3.0.0)
project(HostScanner)

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Wall -Wextra -Wno-write-strings")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Weverything -Wno-c++98-compat-pedantic -Wno-writable-strings -Wno-conversion -Wno-undef -Wno-padded -Wno-switch-enum -Wno-exit-time-destructors -Wno-global-constructors -Wno-shadow -Wno-unused-macros -Wno-old-style-cast")
endif()

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.55.0 COMPONENTS program_options unit_test_framework REQUIRED)
if (Boost_FOUND)
	include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
endif()

file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/test.cpp")
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")

add_executable(HostScanner ${HEADERS} ${SOURCES} main.cpp)
add_executable(TestScanner ${HEADERS} ${SOURCES} test.cpp)

target_link_libraries(HostScanner ${Boost_PROGRAM_OPTIONS_LIBRARY})
target_link_libraries(TestScanner ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

enable_testing()
add_test(ScannerTest TestScanner)