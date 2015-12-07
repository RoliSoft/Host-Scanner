cmake_minimum_required(VERSION 3.0.0)
project(HostScanner)

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
	
	add_definitions(-DWPCAP -DHAVE_REMOTE)
	
	find_path(WINPCAP_INCLUDE_DIR "pcap.h" "${WINPCAP_DIR}/Include")
	find_library(WINPCAP_LIBRARY NAMES "wpcap" PATHS "${WINPCAP_DIR}/Lib")
	
	include_directories(SYSTEM ${WINPCAP_INCLUDE_DIR})
elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Wall -Wextra -Wno-write-strings")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Weverything -Wno-c++98-compat-pedantic -Wno-writable-strings -Wno-conversion -Wno-undef -Wno-padded -Wno-switch-enum -Wno-exit-time-destructors -Wno-global-constructors -Wno-shadow -Wno-unused-macros -Wno-old-style-cast -Wno-undefined-reinterpret-cast")
endif()

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.55.0 COMPONENTS program_options unit_test_framework REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Test.cpp")
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Main.cpp")

add_executable(HostScanner ${HEADERS} ${SOURCES} Main.cpp)
add_executable(TestScanner ${HEADERS} ${SOURCES} Test.cpp)

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	file(GLOB CURL_DLLS ${CURL_INCLUDE_DIR}/../bin/*.dll)
	
	foreach(CURL_DLL ${CURL_DLLS})
		add_custom_command(TARGET HostScanner POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CURL_DLL}" $<TARGET_FILE_DIR:HostScanner>)
		add_custom_command(TARGET TestScanner POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CURL_DLL}" $<TARGET_FILE_DIR:TestScanner>)
	endforeach()
endif()

target_link_libraries(HostScanner ${WINPCAP_LIBRARY} ${CURL_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY})
target_link_libraries(TestScanner ${WINPCAP_LIBRARY} ${CURL_LIBRARY} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

install(TARGETS ${HostScanner} DESTINATION bin)

enable_testing()
add_test(ScannerTest TestScanner)