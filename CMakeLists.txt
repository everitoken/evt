cmake_minimum_required(VERSION 3.5)

# Defines everiToken library target.
project(EVT)

option(ENABLE_MONGODB_SUPPORT   "Build with mongodb support, this enables both mongo_db_plugin and history_plugin" OFF)
option(ENABLE_POSTGRES_SUPPORT  "Build with postgres support, this enables postgres_plugin" OFF)
option(ENABLE_BREAKPAD_SUPPORT  "Build with breakpad support, this enables minidump when crash" OFF)
option(ENABLE_BIND_LIBRARIES    "Build bind libraries" OFF)
option(ENABLE_BENCHMARKS        "Build benchmarks" OFF)
option(ENABLE_COVERAGE_TESTING  "Build EVT for code coverage analysis" OFF)
option(ENABLE_TESTING           "Enable testing targets" ON)
option(ENABLE_COLOR_OUTPUT      "Enable diagnostics color output from compiler" ON)
option(ENABLE_MAINNET_BUILD     "Build EVT for Mainnet" OFF)
option(ENABLE_BUILD_LTO         "Enable LTO when build" OFF)
option(ENABLE_FULL_STATIC_BUILD "Enable full static build" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libraries/fc/CMakeModules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(GNUInstallDirs)
include(VersionMacros)
include(SetupTargetMacros)
include(InstallDirectoryPermissions)

set(BLOCKCHAIN_NAME "EVT")

set(CMAKE_CXX_STANDARD    17)
set(CMAKE_CXX_EXTENSIONS  ON)
set(CXX_STANDARD_REQUIRED ON)

set(VERSION_MAJOR 3)
set(VERSION_MINOR 4)
set(VERSION_PATCH 1)

set(CLI_CLIENT_EXECUTABLE_NAME evtc)
set(GUI_CLIENT_EXECUTABLE_NAME evt)
set(CUSTOM_URL_SCHEME "gcs")
set(INSTALLER_APP_ID "0E523427-37A8-4368-8D5E-AC17FC845110")
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY true)

# http://stackoverflow.com/a/18369825
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
        message(FATAL_ERROR "GCC version must be at least 8.0!")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
        message(FATAL_ERROR "Clang version must be at least 7.0!")
    endif()
endif()

if(WIN32)
    message(FATAL_ERROR "EVT IS NOT SUPPORT BUILDING ON WIN32")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS "ON")

set(CXX_FLAGS
    -Wall
    -Wextra
    -Werror
    -Wno-unused-parameter
    )
string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CXX_FLAGS}")

set(CXX_FLAGS_RELEASE
    -O3
    -DNDEBUG
    )
string(REPLACE ";" " " CMAKE_CXX_FLAGS_RELEASE "${CXX_FLAGS_RELEASE}")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-uninitialized -ftemplate-backtrace-limit=0")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-maybe-uninitialized -fno-builtin-memcmp -no-pie")
    if(ENABLE_FULL_STATIC_BUILD)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
    endif()
endif()

if(USE_PCH)
    include(cotire)
endif()

# add defaults for openssl
if("${OPENSSL_ROOT_DIR}" STREQUAL "")
    if(NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
        set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR})
        set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
    elseif (APPLE)
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
        set(OPENSSL_INCLUDE_DIR "/usr/local/opt/openssl/include")
    elseif(UNIX AND NOT APPLE)
        set(OPENSSL_ROOT_DIR "/usr/include/openssl")
        set(OPENSSL_INCLUDE_DIR "/usr/include/openssl/include")
    else()
        message(FATAL_ERROR "openssl not found and don't know where to look, please specify OPENSSL_ROOT_DIR")
    endif()
endif()

if("${OPENSSL_LIBRARIES}" STREQUAL "")
    if(NOT "$ENV{OPENSSL_LIBRARIES}" STREQUAL "")
        set(OPENSSL_LIBRARIES $ENV{OPENSSL_LIBRARIES})
    elseif (APPLE)
        set(OPENSSL_LIBRARIES "/usr/local/opt/openssl/lib")
    elseif(UNIX AND NOT APPLE)
        set(OPENSSL_LIBRARIES "/usr/include/openssl")
    else()
        message(FATAL_ERROR "openssl libs not found and don't know where to look, please specify OPENSSL_LIBRARIES")
    endif()
endif()

if(UNIX)
    if(APPLE)
        set(whole_archive_flag "-force_load")
        set(no_whole_archive_flag "")
    else()
        set(whole_archive_flag "--whole-archive")
        set(no_whole_archive_flag "--no-whole-archive")
    endif()
else()
    set(whole_archive_flag "--whole-archive")
    set(no_whole_archive_flag "--no-whole-archive")
endif()

if(ENABLE_FULL_STATIC_BUILD)
    set(Boost_USE_STATIC_LIBS ON CACHE STRING "ON or OFF")
else()
    set(Boost_USE_STATIC_LIBS OFF CACHE STRING "ON or OFF")
endif()

FIND_PACKAGE(Boost 1.69 REQUIRED COMPONENTS
    thread
    date_time
    filesystem
    system
    program_options
    serialization
    chrono
    unit_test_framework
    context
    locale
    iostreams
    timer)

if(ENABLE_COLOR_OUTPUT)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcolor-diagnostics")
    elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
    endif()
endif()

# based on http://www.delorie.com/gnu/docs/gdb/gdb_70.html
# uncomment this line to tell GDB about macros (slows compile times)
# set( CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -gdwarf-2 -g3" )

if(ENABLE_COVERAGE_TESTING)
    SET(CMAKE_CXX_FLAGS "--coverage ${CMAKE_CXX_FLAGS}")
    find_program( LCOV_PATH  lcov )
    find_program( GENHTML_PATH NAMES genhtml)
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR ENABLE_BREAKPAD_SUPPORT)
    message(STATUS "Build EVT with symbols")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif()

if(ENABLE_BUILD_LTO)
    message(STATUS "Build EVT with link-time optimization")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fuse-linker-plugin -flto -ffat-lto-objects")
endif()

include_directories(libraries/rocksdb/include)

if("${EVT_ROOT_KEY}" STREQUAL "")
   set(EVT_ROOT_KEY "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV")
endif()

message( STATUS "Using '${EVT_ROOT_KEY}' as public key for evt account" )

if(ENABLE_TESTING)
    enable_testing()
endif()

add_subdirectory(libraries)
add_subdirectory(plugins)
add_subdirectory(programs)

if(ENABLE_BIND_LIBRARIES)
    add_subdirectory(bind)
endif()

if(ENABLE_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(ENABLE_TESTING)
    add_subdirectory(unittests)
endif()

include(installer)
