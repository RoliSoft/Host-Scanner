cmake_minimum_required(VERSION 3.0.0)
project(HostScanner)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(APP_MAJOR_VERSION 0)
set(APP_MINOR_VERSION 2)
set(APP_PATCH_VERSION 0)
set(APP_VERSION "${APP_MAJOR_VERSION}.${APP_MINOR_VERSION}.${APP_PATCH_VERSION}")

if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git/refs/heads/master")
	file(READ "${CMAKE_CURRENT_SOURCE_DIR}/.git/refs/heads/master" APP_COMMIT)
	string(REGEX MATCH "[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]" APP_COMMIT "${APP_COMMIT}")
	set(APP_VERSION "${APP_MAJOR_VERSION}.${APP_MINOR_VERSION}.${APP_PATCH_VERSION}-git~${APP_COMMIT}")
endif()

add_definitions(-DVERSION_MAJOR=${APP_MAJOR_VERSION} -DVERSION_MINOR=${APP_MINOR_VERSION} -DVERSION_PATCH=${APP_PATCH_VERSION} -DVERSION_STRING="${APP_VERSION}")

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /MP")
	
	add_definitions(-DHAVE_WPCAP -DWPCAP -DHAVE_REMOTE -D_ENABLE_ATOMIC_ALIGNMENT_FIX)
	
	find_path(WINPCAP_INCLUDE_DIR "pcap.h" "${WINPCAP_DIR}/Include")
	find_library(WINPCAP_LIBRARY NAMES "wpcap" PATHS "${WINPCAP_DIR}/Lib")
	
	include_directories(SYSTEM ${WINPCAP_INCLUDE_DIR})
elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Wall -Wextra -Wno-write-strings")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread -Weverything -Wno-c++98-compat-pedantic -Wno-writable-strings -Wno-conversion -Wno-undef -Wno-padded -Wno-switch-enum -Wno-exit-time-destructors -Wno-global-constructors -Wno-shadow -Wno-unused-macros -Wno-old-style-cast -Wno-undefined-reinterpret-cast -Wno-disabled-macro-expansion -Wno-missing-prototypes")
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

if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/conanbuildinfo.cmake")
	include(conanbuildinfo.cmake)
	conan_basic_setup()
endif()

if (NOT DEFINED WITHOUT_ZLIB OR NOT ${WITHOUT_ZLIB} EQUAL 1)
	if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
		set(ADDITIONAL_BOOST_COMPONENTS "zlib")
	else()
		find_package(ZLIB REQUIRED)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lz")
	endif()
	add_definitions(-DHAVE_ZLIB)
else()
	message(STATUS "HostScanner will be compiled without zlib; compressed data files will not be loadable.")
endif()

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.55.0 COMPONENTS system regex iostreams filesystem date_time program_options unit_test_framework ${ADDITIONAL_BOOST_COMPONENTS} REQUIRED)
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

find_package(SQLite 3 REQUIRED)
include_directories(SYSTEM ${SQLITE_INCLUDE_DIR})

file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Test.cpp")
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Main.cpp")

add_executable(HostScanner ${HEADERS} ${SOURCES} Main.cpp)
add_executable(TestScanner ${HEADERS} ${SOURCES} Test.cpp)

file(GLOB MISC_SRCS "*.*")
source_group("Miscellaneous" FILES ${MISC_SRCS})

file(GLOB IDENTIFIER_SRCS "*Identifier.*")
source_group("Identifiers" FILES ${IDENTIFIER_SRCS})

file(GLOB TOKENIZER_SRCS "*Tokenizer.*")
source_group("Tokenizers" FILES ${TOKENIZER_SRCS})

file(GLOB LOOKUP_SRCS "*Lookup.*")
source_group("Lookups" FILES ${LOOKUP_SRCS})

file(GLOB MATCHER_SRCS "*Matcher.*" "BannerProcessor.*")
source_group("Matchers" FILES ${MATCHER_SRCS})

file(GLOB ACTIVE_SRCS "*Scanner*" "*Pinger*")
source_group("Scanners/Active" FILES ${ACTIVE_SRCS})

file(GLOB EXTERNAL_SRCS "Nmap*.*")
source_group("Scanners/External" FILES ${EXTERNAL_SRCS})

file(GLOB PASSIVE_SRCS "Shodan*.*" "Censys*.*" "Looquer*.*" "Passive*.*")
source_group("Scanners/Passive" FILES ${PASSIVE_SRCS})

file(GLOB FACTORY_SRCS "*Factory.*")
source_group("Factories" FILES ${FACTORY_SRCS})

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

target_link_libraries(HostScanner ${WINPCAP_LIBRARY} ${CURL_LIBRARY} ${SQLITE_LIBRARIES} ${Boost_LIBRARIES})
target_link_libraries(TestScanner ${WINPCAP_LIBRARY} ${CURL_LIBRARY} ${SQLITE_LIBRARIES} ${Boost_LIBRARIES})

install(TARGETS ${HostScanner} DESTINATION bin)

enable_testing()
add_test(ScannerTest TestScanner)