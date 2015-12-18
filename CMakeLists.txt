cmake_minimum_required(VERSION 3.0.0)
project(HostScanner)

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
	
	add_definitions(-DHAVE_WPCAP -DWPCAP -DHAVE_REMOTE)
	
	find_path(WINPCAP_INCLUDE_DIR "pcap.h" "${WINPCAP_DIR}/Include")
	find_library(WINPCAP_LIBRARY NAMES "wpcap" PATHS "${WINPCAP_DIR}/Lib")
	
	include_directories(SYSTEM ${WINPCAP_INCLUDE_DIR})
elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Wall -Wextra -Wno-write-strings")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Weverything -Wno-c++98-compat-pedantic -Wno-writable-strings -Wno-conversion -Wno-undef -Wno-padded -Wno-switch-enum -Wno-exit-time-destructors -Wno-global-constructors -Wno-shadow -Wno-unused-macros -Wno-old-style-cast -Wno-undefined-reinterpret-cast -Wno-disabled-macro-expansion")
else()
	message(STATUS "Unrecognized compiler; build may not succeed.")
endif()

if (${BUILD_STATIC})
	if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
		set(BUILD_SHARED_LIBRARIES OFF)
		set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
	else()
		message(FATAL_ERROR "Static builds not yet supported for this compiler.")
	endif()
endif()

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.55.0 COMPONENTS system filesystem program_options unit_test_framework REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

if (NOT DEFINED WITHOUT_CURL OR NOT ${WITHOUT_CURL} EQUAL 1)
	find_package(CURL)
	if (${CURL_FOUND})
		include_directories(${CURL_INCLUDE_DIR})
		add_definitions(-DHAVE_CURL)
	else()
		message(STATUS "HostScanner will be compiled without curl; features relying on online APIs will not be available.")
	endif()
endif()

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

if (${BUILD_STATIC})
	set_target_properties(HostScanner PROPERTIES LINK_SEARCH_START_STATIC 1)
	set_target_properties(HostScanner PROPERTIES LINK_SEARCH_END_STATIC 1)
	set_target_properties(TestScanner PROPERTIES LINK_SEARCH_START_STATIC 1)
	set_target_properties(TestScanner PROPERTIES LINK_SEARCH_END_STATIC 1)
endif()

target_link_libraries(HostScanner ${WINPCAP_LIBRARY} ${CURL_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY})
target_link_libraries(TestScanner ${WINPCAP_LIBRARY} ${CURL_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

install(TARGETS ${HostScanner} DESTINATION bin)

enable_testing()
add_test(ScannerTest TestScanner)